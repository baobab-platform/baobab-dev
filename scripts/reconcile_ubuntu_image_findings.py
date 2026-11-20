"""Correlate the locked binary payloads and review source correspondence at the Ubuntu tag."""
import argparse
import hashlib
import io
import json
import re
import subprocess
import tarfile
from pathlib import Path

from audit_ubuntu_kernel_fix_history import (
    LOCK, SOURCE_REPO, cached_patch_id, changed_paths, commit_metadata, ensure_candidate_object, run,
)
from verify_ubuntu_binary_package_arch import archive_manifest, installed_manifest


def payloads(root):
    manifests = {}
    for arch, expected in LOCK.binary_artifact_sha256.items():
        folder = root / arch
        deb = folder / f"linux-libc-dev_{LOCK.package_version}_{arch}.deb"
        installed = installed_manifest(folder / "installed-content-manifest.tsv")
        if hashlib.sha256(deb.read_bytes()).hexdigest() != expected or archive_manifest(deb) != installed:
            raise ValueError(f"{arch} package or installed payload differs from the reviewed evidence")
        manifests[arch] = {row["path"]: row["value"] for row in installed if row["kind"] != "dir"}
    return manifests


def source_review(witness, reviews, tag):
    """Apply a human-reviewed observation only to the precise code examined."""
    if tag != reviews["reviewed_ubuntu_tag"]:
        return "REVIEW_REQUIRED_TAG_CHANGED"
    identity = {k: witness[k] for k in ("cve", "kind", "upstream", "ubuntu")}
    if identity not in reviews["leads"]:
        return "REVIEW_REQUIRED_UNKNOWN_LEAD"
    if not (witness["same_ordered_edits"] and witness["stable_patch_equivalence"]):
        return "REVIEW_REQUIRED_EDIT_EVIDENCE_INCOMPLETE"
    entry = reviews["source_reviews"].get(witness["ubuntu"])
    paths = witness["tag_path_comparison"]
    if (not entry or entry["cve"] != witness["cve"] or not entry["paths"]
            or entry["edit_sha256"] != witness["ubuntu_edit_sha256"]
            or entry["edit_sha256"] != witness["upstream_edit_sha256"]
            or entry["patch_id"] != witness["ubuntu_patch_id"]
            or entry["patch_id"] != witness["upstream_patch_id"]
            or any(paths.count(item) != 1 for item in entry["paths"])
            or len({item["path"] for item in paths}) != len(paths)):
        return "REVIEW_REQUIRED_PATH_EVIDENCE_CHANGED"
    return entry["observation"]


def payload_contents(root, arch, expected):
    """Inspect literal includes and content signatures in the locked Debian archive."""
    folder = root / arch
    deb = folder / f"linux-libc-dev_{LOCK.package_version}_{arch}.deb"
    if hashlib.sha256(deb.read_bytes()).hexdigest() != expected:
        raise ValueError("unreviewed Debian package")
    raw = subprocess.run(["dpkg-deb", "--fsys-tarfile", str(deb)], capture_output=True,
                         check=True, timeout=90).stdout
    headers, docs, other, objects, executable, computed = [], [], [], [], [], []
    includes = {}
    with tarfile.open(fileobj=io.BytesIO(raw)) as payload:
        for member in payload:
            if member.isdir():
                continue
            path = "/" + member.name.removeprefix("./")
            if not member.isfile():
                other.append(path)
                continue
            data = payload.extractfile(member).read()
            if data.startswith((b"\x7fELF", b"!<arch>\n", b"!<thin>\n")):
                objects.append(path)
            if member.mode & 0o111:
                executable.append(path)
            if path.startswith("/usr/include/") and path.endswith(".h"):
                headers.append(path)
                # Join continued preprocessing lines before examining include directives.
                for directive in re.findall(rb"(?m)^\s*#\s*include\s*([^\n]+)",
                                            data.replace(b"\\\n", b"")):
                    target = re.match(rb'[<"]([^>"]+)[>"]', directive.strip())
                    if target:
                        name = target[1].decode("utf-8", "replace").rsplit("/", 1)[-1]
                        includes.setdefault(name, set()).add(path)
                    else:
                        computed.append(path)
            elif path.startswith("/usr/share/doc/linux-libc-dev/"):
                docs.append(path)
            else:
                other.append(path)
    return dict(header_count=len(headers), documentation=sorted(docs), other_entries=sorted(other),
                executable_mode_files=sorted(executable), elf_or_archive_files=sorted(objects),
                headers_with_nonliteral_includes=sorted(set(computed))), includes


def image_findings(root, contents=None):
    def records(name):
        rows = json.loads((root / name).read_bytes())["records"]
        index = {row["cve"]: row for row in rows}
        if len(rows) != LOCK.inventory_count or len(index) != len(rows):
            raise ValueError("unexpected evidence inventory: " + name)
        return index

    osv_input = json.loads((root / "canonical-osv-evidence.json").read_bytes())
    if (osv_input["source_commit"] != LOCK.canonical_osv_commit
            or osv_input["target_binary_version"] != LOCK.package_version):
        raise ValueError("unexpected Canonical OSV revision or binary version")
    osv = records("canonical-osv-evidence.json")
    paths = records("ubuntu-source-paths.json")
    manifests = payloads(root)
    if contents is None:
        contents = {arch: payload_contents(root, arch, digest)
                    for arch, digest in LOCK.binary_artifact_sha256.items()}
    rows = []
    for cve in sorted(LOCK.observed_kernel_cves):
        entries = osv[cve]["ubuntu_26_04_linux_source_entries"]
        source = paths[cve]
        if source["ubuntu_release_tag_commit"] != LOCK.ubuntu_tag_commit:
            raise ValueError("source paths refer to another Ubuntu tag")
        shipped = {}
        for arch, files in manifests.items():
            matches = {}
            for item in source["upstream_path_correspondence"]:
                for path in [item["upstream_path"], *item.get("same_basename_candidates", [])]:
                    if "include/uapi/" in path:
                        suffix = "/" + path.split("include/uapi/", 1)[1]
                        matches.update({p: digest for p, digest in files.items()
                                        if p.startswith("/usr/include/") and p.endswith(suffix)})
            shipped[arch] = matches
        names = {Path(item["upstream_path"]).name for item in source["upstream_path_correspondence"]}
        literal_includes = {arch: {n: sorted(index[n]) for n in sorted(names & index.keys())}
                            for arch, (_, index) in contents.items()}
        rows.append(dict(cve=cve, shipped_literal_include_basename_matches=literal_includes, source_version_affected=any(
            e["target_version_in_affected_versions"] for e in entries),
            binary_version_listed=any(LOCK.package_version in e["linux_libc_dev_binary_versions"]
                                      for e in entries),
            missing_at_tag=source["upstream_paths_missing_from_ubuntu_snapshot"],
            direct_uapi_path_candidates=shipped, disposition="under_investigation"))
    return rows


def edit_digest(repo, commit):
    """Fingerprint the ordered changed lines with file identities and whitespace intact."""
    diff = subprocess.run(["git", "-C", str(repo), "diff", "--no-renames", "--no-ext-diff",
                           "--no-textconv", "--unified=0", commit + "^", commit],
                          capture_output=True, check=True, timeout=120).stdout
    lines = [line for line in diff.splitlines(keepends=True)
             if line.startswith((b"diff --git ", b"+", b"-", b"new file mode ",
                                 b"deleted file mode ", b"old mode ", b"new mode "))]
    if not lines or b"Binary files " in diff or b"GIT binary patch" in diff:
        return None
    return hashlib.sha256(b"".join(lines)).hexdigest()


def tag_witnesses(repo, store, root):
    tag = LOCK.ubuntu_tag_commit
    if run(repo, "remote", "get-url", "origin") != SOURCE_REPO or run(repo, "rev-parse", "HEAD") != tag:
        raise ValueError("unexpected Ubuntu checkout")
    leads = json.loads(Path("security/evidence/dev10-run533-leads.json").read_bytes())
    references = {row["cve"]: set(row["candidate_upstream_fix_references"])
                  for row in json.loads((root / "affected-source-files.json").read_bytes())["records"]}
    remotes = {"stable": "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
               "linus": "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"}
    cache = {}
    records = []
    for lead in leads["leads"]:
        up, down, kind = lead["upstream"], lead["ubuntu"], lead["kind"]
        if f"https://git.kernel.org/{kind}/c/{up}" not in references[lead["cve"]]:
            raise ValueError("historical lead differs from pinned CNA references")
        run(repo, "merge-base", "--is-ancestor", down, tag)
        meta = commit_metadata(repo, down)
        paths = changed_paths(repo, down, meta["parents"])
        post = run(repo, "ls-tree", "-r", down, "--", *paths).splitlines()
        final = run(repo, "ls-tree", "-r", tag, "--", *paths).splitlines()
        def blobs(lines):
            return {line.split("\t", 1)[1]: line.split("\t", 1)[0] for line in lines}
        before, after = blobs(post), blobs(final)
        upstream_repo, status = repo, "exact_ancestor"
        if up != down:
            upstream_repo, status, _ = ensure_candidate_object(store, up, kind, remotes)
        upstream_pid = cached_patch_id(upstream_repo, up, cache) if upstream_repo else None
        downstream_pid = cached_patch_id(repo, down, cache)
        upstream_edit = edit_digest(upstream_repo, up) if upstream_repo else None
        ubuntu_edit = edit_digest(repo, down)
        records.append(dict(**lead, ubuntu_subject=meta["subject"], upstream_object=status,
                            same_ordered_edits=bool(upstream_edit and upstream_edit == ubuntu_edit),
                            upstream_edit_sha256=upstream_edit, ubuntu_edit_sha256=ubuntu_edit,
                            stable_patch_equivalence=bool(upstream_pid and upstream_pid == downstream_pid),
                            upstream_patch_id=upstream_pid, ubuntu_patch_id=downstream_pid,
                            tag_path_comparison=[dict(path=p, at_commit=before.get(p), at_tag=after.get(p))
                                                 for p in paths], disposition="under_investigation"))
    for witness in records:
        witness["reviewed_source_observation"] = source_review(witness, leads, tag)
    return records


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for opt in ("evidence", "ubuntu", "candidates", "output"):
        parser.add_argument("--" + opt, required=True, type=Path)
    args = parser.parse_args()
    contents = {arch: payload_contents(args.evidence, arch, digest)
                for arch, digest in LOCK.binary_artifact_sha256.items()}
    findings = image_findings(args.evidence, contents)
    packages = {arch: summary for arch, (summary, _) in contents.items()}
    report = dict(ubuntu_commit=LOCK.ubuntu_tag_commit, package_version=LOCK.package_version,
                  deb_sha256=LOCK.binary_artifact_sha256, findings=findings,
                  installed_package_contents=packages,
                  source_witnesses=tag_witnesses(args.ubuntu, args.candidates, args.evidence))
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
