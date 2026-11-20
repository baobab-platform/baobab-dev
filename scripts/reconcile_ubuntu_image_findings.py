"""Correlate the locked binary payloads and review source correspondence at the Ubuntu tag."""
import argparse
import hashlib
import json
import subprocess
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


def image_findings(root):
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
        rows.append(dict(cve=cve, source_version_affected=any(
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
    return records


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for opt in ("evidence", "ubuntu", "candidates", "output"):
        parser.add_argument("--" + opt, required=True, type=Path)
    args = parser.parse_args()
    report = dict(ubuntu_commit=LOCK.ubuntu_tag_commit, package_version=LOCK.package_version,
                  deb_sha256=LOCK.binary_artifact_sha256, findings=image_findings(args.evidence),
                  source_witnesses=tag_witnesses(args.ubuntu, args.candidates, args.evidence))
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
