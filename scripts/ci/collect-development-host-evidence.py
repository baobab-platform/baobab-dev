#!/usr/bin/env python3
"""Collect read-only Linux and Docker observations from a named development workspace."""

import argparse
from collections import Counter
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


SOCKETS = ("/var/run/docker.sock", "/var/run/docker-host.sock")
KERNEL_FLAGS = ("ANDROID_BINDER_IPC", "ANDROID_BINDERFS", "EXT4_FS", "NTFS_FS", "NTFS3_FS")
NTFS_TYPES = {"ntfs", "ntfs3", "fuseblk", "fuse.ntfs-3g"}
CONTAINER_ID = re.compile(r"[a-f0-9]{64}")
DIGEST = re.compile(r"sha256:[a-f0-9]{64}")
TOKEN = re.compile(r"[A-Za-z0-9_.+:-]{1,160}")


def read_text(path):
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read(1024 * 1024)
    except (OSError, UnicodeError):
        return ""


def safe_token(value):
    return value if isinstance(value, str) and TOKEN.fullmatch(value) else None


def unescape_mount(value):
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), value)


def mounts_from_linux(text):
    mounts = []
    for line in text.splitlines():
        before, separator, after = line.partition(" - ")
        left, right = before.split(), after.split()
        if separator and len(left) >= 6 and len(right) >= 3:
            mounts.append((unescape_mount(left[4]), safe_token(right[0]), set(left[5].split(","))))
    return mounts


def mount_at(mounts, path):
    if not isinstance(path, str) or not os.path.isabs(path):
        return None
    real = os.path.realpath(path)
    matching = [entry for entry in mounts if real == entry[0] or real.startswith(entry[0].rstrip("/") + "/")]
    if not matching:
        return None
    _, fstype, flags = max(reversed(matching), key=lambda entry: len(entry[0]))
    return {"filesystem": fstype, "read_only": "ro" in flags,
            "nodev": "nodev" in flags, "nosuid": "nosuid" in flags}


def kernel_config(release):
    text = read_text(f"/boot/config-{release}")
    source = "boot_config" if text else None
    if not text:
        try:
            with gzip.open("/proc/config.gz", "rt", encoding="utf-8") as handle:
                text = handle.read(1024 * 1024)
                source = "proc_config"
        except (OSError, UnicodeError):
            pass
    values = {}
    for flag in KERNEL_FLAGS:
        enabled = re.search(rf"(?m)^CONFIG_{flag}=([ymn])$", text)
        disabled = re.search(rf"(?m)^# CONFIG_{flag} is not set$", text)
        values[flag] = enabled[1] if enabled else "n" if disabled else None
    return {"source": source, "options": values}


def installed_kernel_packages(release):
    packages = {}
    if not safe_token(release):
        return packages
    for prefix in ("linux-image-", "linux-image-unsigned-"):
        name = prefix + release
        try:
            result = subprocess.run(["dpkg-query", "-W", "-f=${db:Status-Status}\t${Version}", name],
                                    text=True, capture_output=True, check=True, timeout=10)
        except (OSError, subprocess.SubprocessError):
            continue
        status, _, version = result.stdout.strip().partition("\t")
        if status == "installed" and safe_token(version):
            packages[name] = version
    return packages


def devices_from_linux():
    binder = set()
    binder_dac = set()
    blocks = set()
    for directory, directories, files in os.walk("/dev", followlinks=False):
        directories[:] = [name for name in directories if name not in {"shm", "mqueue", "pts", "fd"}]
        for name in files:
            path = os.path.join(directory, name)
            try:
                metadata = os.stat(path)
            except OSError:
                continue
            if stat.S_ISBLK(metadata.st_mode):
                blocks.add(metadata.st_rdev)
            if "binder" in name.lower() and stat.S_ISCHR(metadata.st_mode):
                binder.add(metadata.st_rdev)
                if os.access(path, os.R_OK | os.W_OK, effective_ids=True):
                    binder_dac.add(metadata.st_rdev)
    return {"binder_named_device_count": len(binder), "binder_dac_read_write_count": len(binder_dac),
            "block_device_count": len(blocks)}


def docker_json(socket, *args):
    env = {key: value for key, value in os.environ.items()
           if key not in {"DOCKER_CONTEXT", "DOCKER_HOST", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"}}
    try:
        result = subprocess.run(["docker", "--host", f"unix://{socket}", *args], env=env,
                                text=True, capture_output=True, check=True, timeout=35)
        value = json.loads(result.stdout)
        return value if isinstance(value, dict) else None
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


def summarize_daemon(value):
    security = value.get("SecurityOptions") or []
    plugins = value.get("Plugins") or {}
    authorizers = plugins.get("Authorization")
    identity = value.get("ID")
    return {"version": safe_token(value.get("ServerVersion")),
            "kernel_release": safe_token(value.get("KernelVersion")),
            "rootless": "name=rootless" in security,
            "authorization_plugin_count": len(authorizers or []) if "Authorization" in plugins else None,
            "identity_sha256": hashlib.sha256(identity.encode()).hexdigest() if identity else None}


def snapshot(workspace):
    release = os.uname().release
    os_data = dict(line.split("=", 1) for line in read_text("/etc/os-release").splitlines() if "=" in line)
    status = dict(line.split(":", 1) for line in read_text("/proc/self/status").splitlines() if ":" in line)
    mounts = mounts_from_linux(read_text("/proc/self/mountinfo"))
    sockets = {}
    daemon = None
    detail = None
    for socket in SOCKETS:
        try:
            inode = os.stat(socket)
        except OSError:
            continue
        if not stat.S_ISSOCK(inode.st_mode):
            continue
        value = docker_json(socket, "info", "--format", "{{json .}}")
        sockets[socket] = {"mode": f"{stat.S_IMODE(inode.st_mode):04o}",
                           "dac_write": os.access(socket, os.W_OK, effective_ids=True),
                           "daemon_read_api": value is not None}
        if value is not None and daemon is None:
            daemon, detail = socket, value
    data = {
        "kernel": {"release": safe_token(release), "machine": safe_token(os.uname().machine),
                   "config": kernel_config(release), "installed_packages": installed_kernel_packages(release)},
        "userspace": {key.lower(): safe_token(os_data.get(key, "").strip('"')) for key in ("ID", "VERSION_ID")},
        "process": {"uid": os.geteuid(), **{key: safe_token(status.get(key, "").strip())
                    for key in ("CapEff", "CapBnd", "NoNewPrivs", "Seccomp")}},
        "devices": devices_from_linux(),
        "mounts": {"root": mount_at(mounts, "/"), "workspace": mount_at(mounts, workspace),
                   "ntfs_family_counts": dict(Counter(fstype for _, fstype, _ in mounts if fstype in NTFS_TYPES))},
        "docker": {"sockets": sockets, "endpoint": daemon,
                   "server": summarize_daemon(detail) if detail is not None else None},
    }
    return data, detail, mounts


def summarize_container(value, host_mounts):
    config = value["HostConfig"]
    security = config.get("SecurityOpt") or []

    def caps(key):
        return [name for raw in config.get(key) or [] if (name := safe_token(raw))]

    # Mount source and destination paths never leave the runner. Determine
    # backing filesystems from the daemon host's mount table.
    mounts = [{"kind": safe_token(mount.get("Type")), "read_write": mount.get("RW"),
               "docker_socket": mount.get("Source") in SOCKETS or mount.get("Destination") in SOCKETS,
               "host_backing": mount_at(host_mounts, mount.get("Source"))}
              for mount in value.get("Mounts") or []]
    image = value["Image"]
    if not isinstance(image, str) or not DIGEST.fullmatch(image):
        raise ValueError("Docker returned an invalid workspace image identity")
    return {"effective_image_id": image, "privileged": config["Privileged"],
            "capabilities_added": caps("CapAdd"), "capabilities_dropped": caps("CapDrop"),
            "seccomp_unconfined": any(option in {"seccomp=unconfined", "seccomp:unconfined"} for option in security),
            "explicit_devices": len(config.get("Devices") or []),
            "device_cgroup_rules": len(config.get("DeviceCgroupRules") or []),
            "device_requests": len(config.get("DeviceRequests") or []), "mounts": mounts}


def running_container(socket, container_id, mounts):
    value = docker_json(socket, "container", "inspect", "--format", "{{json .}}", container_id)
    if not value or value.get("Id") != container_id or not value.get("State", {}).get("Running"):
        raise ValueError("Could not inspect the declared running container on the local Docker daemon")
    return summarize_container(value, mounts)


def daemon_identity(snapshot_data):
    return (snapshot_data["docker"]["server"] or {}).get("identity_sha256")


def matches_running_kernel(host, namespace):
    keys = ("release", "machine")
    return all(host["kernel"][key] and host["kernel"][key] == namespace["kernel"][key] for key in keys)


def read_snapshot(path):
    return json.loads(path.read_bytes())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    namespace = commands.add_parser("namespace")
    namespace.add_argument("--workspace", type=Path)
    host = commands.add_parser("host")
    host.add_argument("--workspace", type=Path, required=True)
    host.add_argument("--workspace-id", required=True)
    host.add_argument("--workspace-snapshot", type=Path, required=True)
    host.add_argument("--child-id")
    host.add_argument("--child-snapshot", type=Path)
    host.add_argument("--config", type=Path, required=True)
    host.add_argument("--base-image", required=True)
    host.add_argument("--base-image-id", required=True)
    host.add_argument("--source", required=True)
    args = parser.parse_args()

    data, daemon, mounts = snapshot(str(args.workspace.resolve()) if args.workspace else None)
    if args.command == "namespace":
        print(json.dumps(data, indent=2, sort_keys=True))
        return
    if not re.fullmatch(r"[a-f0-9]{40}", args.source) or not re.fullmatch(
            r"ghcr\.io/baobab-platform/baobab-dev:[0-9.]+@sha256:[a-f0-9]{64}", args.base_image
    ) or not DIGEST.fullmatch(args.base_image_id):
        parser.error("An exact source commit and immutable Baobab reference image are required")
    if not CONTAINER_ID.fullmatch(args.workspace_id) or bool(args.child_id) != bool(args.child_snapshot) or (
            args.child_id and not CONTAINER_ID.fullmatch(args.child_id)):
        parser.error("The workspace and any Docker-launched child must have exact container IDs")
    socket = data["docker"]["endpoint"]
    if not socket or daemon is None:
        parser.error("The host must be able to inspect the local Docker daemon")
    data["mounts"]["docker_data_root"] = mount_at(mounts, daemon.get("DockerRootDir"))
    workspace_ns = read_snapshot(args.workspace_snapshot)
    workspace = {"namespace": workspace_ns, "docker_config": running_container(socket, args.workspace_id, mounts)}
    child = ({"namespace": read_snapshot(args.child_snapshot),
              "docker_config": running_container(socket, args.child_id, mounts)} if args.child_id else None)
    host_id, workspace_id = daemon_identity(data), daemon_identity(workspace_ns)
    evidence = {"schema": "baobab.dev10.development-host-observation.v1", "source_sha": args.source,
                "scope": "github_hosted_reference_devcontainer" if os.environ.get("GITHUB_ACTIONS") == "true"
                else "operator_observed_reference_devcontainer",
                "run_id": safe_token(os.environ.get("GITHUB_RUN_ID")),
                "run_attempt": safe_token(os.environ.get("GITHUB_RUN_ATTEMPT")),
                "reference_config_sha256": hashlib.sha256(args.config.read_bytes()).hexdigest(),
                "reference_base_image": args.base_image, "reference_base_image_id": args.base_image_id,
                "host": data, "workspace": workspace,
                "docker_launched_child": child,
                "workspace_daemon_matches_host": host_id == workspace_id if host_id and workspace_id else None,
                "workspace_kernel_matches_host": matches_running_kernel(data, workspace_ns),
                "child_kernel_matches_host": matches_running_kernel(data, child["namespace"]) if child else None}
    print(json.dumps(evidence, indent=2, sort_keys=True))


if __name__ == "__main__":
    sys.exit(main())
