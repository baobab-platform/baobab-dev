#!/usr/bin/env python3
"""DEV-10 independent VEX authorisation gate (never an approval issuer).

Consumes a FULL unfiltered Trivy JSON inventory and a separately signed,
CVE-specific decision. The trust bundle MUST come from a protected governance
source outside the PR/change being assessed, not from the image/branch itself.
Produces a minimal OpenVEX projection only AFTER authorisation verification.
No trusted authority or missing evidence => fail closed.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

CVE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
SHA = re.compile(r"^[a-f0-9]{64}$")
ALLOWED = {"vulnerable_code_not_present", "component_not_present",
           "vulnerable_code_not_in_execute_path"}
CONTEXT = "https://openvex.dev/ns/v0.2.0"


class PolicyError(ValueError):
    pass


def canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def time_utc(value: str) -> dt.datetime:
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("timezone missing")
        return parsed.astimezone(dt.timezone.utc)
    except (ValueError, AttributeError) as exc:
        raise PolicyError("invalid offset-aware timestamp") from exc


def require(condition: bool, why: str) -> None:
    if not condition:
        raise PolicyError(why)


def verify_signature(decision: dict, signature_b64: str, public_key_pem: str) -> None:
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except ValueError as exc:
        raise PolicyError("invalid approval signature encoding") from exc
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "decision").write_bytes(canonical(decision))
        (root / "signature").write_bytes(signature)
        (root / "key.pem").write_text(public_key_pem)
        proc = subprocess.run(
            ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(root / "key.pem"),
             "-rawin", "-in", str(root / "decision"), "-sigfile", str(root / "signature")],
            capture_output=True, timeout=10, check=False)
        require(proc.returncode == 0, "independent approval signature invalid")


def findings(report: dict) -> dict[tuple[str, str, str], dict]:
    require(isinstance(report.get("Results"), list) and report["Results"],
            "missing full Trivy Results inventory")
    found = {}
    for result in report["Results"]:
        for item in result.get("Vulnerabilities") or []:
            if item.get("Severity") not in {"HIGH", "CRITICAL"}:
                continue
            cve, pkg, version = (item.get("VulnerabilityID"),
                                 item.get("PkgName"), item.get("InstalledVersion"))
            require(isinstance(cve, str) and isinstance(pkg, str)
                    and isinstance(version, str), "incomplete scanner finding")
            key = (cve, pkg, version)
            found[key] = item
    return found


def qualify(report: dict, signed: dict, trust: dict, *,
            image_digest: str, platform: str, image_purl: str,
            register: dict, now: dt.datetime | None = None) -> tuple[dict, list]:
    now = now or dt.datetime.now(dt.timezone.utc)
    require(SHA.fullmatch(image_digest) is not None, "invalid exact OCI digest")
    require(platform in ("linux/amd64", "linux/arm64"), "unsupported architecture")
    require("@" + "sha256:" + image_digest in image_purl and image_purl.startswith("pkg:oci/"),
            "VEX image PURL must include exact OCI sha256")
    require(signed.get("signature") and isinstance(signed.get("decision"), dict),
            "unsigned or missing approval")
    d = signed["decision"]
    require(d.get("schema") == "baobab.dev10.vex-approval.v1", "unknown approval schema")
    principal = d.get("approver_principal")
    key_id = d.get("approval_key_id")
    require(bool(principal) and bool(key_id), "missing independent approver")
    authority = (trust.get("authorised_approvers") or {}).get(principal, {})
    require(authority.get("key_id") == key_id and authority.get("permission")
            == "security:vex:approve", "approver lacks governed security authority")
    require(authority.get("scope") == "baobab-platform/baobab-dev",
            "approval grant scope mismatch")
    require(key_id not in trust.get("revoked_keys", []), "approver key revoked")
    require(d.get("decision_id") not in trust.get("revoked_decisions", []),
            "approval decision revoked")
    require(d.get("preparer_principal") != principal
            and d.get("engineering_author_principal") != principal,
            "maker-checker separation violated")
    require(d.get("decision") in ("approved", "rejected", "needs_evidence"),
            "unknown reviewer decision")
    require(d.get("image_digest") == "sha256:" + image_digest
            and d.get("platform") == platform and d.get("image_purl") == image_purl,
            "approval image or architecture mismatch")
    require(d.get("source_revision") and re.fullmatch(r"[a-f0-9]{40}", d["source_revision"]),
            "source revision not immutable")
    require(SHA.fullmatch(d.get("evidence_sha256") or "") is not None,
            "missing evidence content digest")
    require(time_utc(d["issued_at"]) <= now < time_utc(d["expires_at"]),
            "approval expired or not yet active")
    require(time_utc(authority["valid_from"]) <= now < time_utc(authority["valid_until"]),
            "reviewer appointment inactive or expired")
    require(d.get("raw_trivy_sha256") == hashlib.sha256(canonical(report)).hexdigest(),
            "reviewed scanner evidence does not match this unfiltered inventory")
    verify_signature(d, signed["signature"], authority["public_key_pem"])
    require(d["decision"] == "approved", "reviewer rejected or requested evidence")
    require(register.get("advisory_count") == 295
            and len(register.get("records", [])) == 295,
            "incomplete canonical applicability register")
    by_cve = {x["cve"]: x for x in register["records"]}
    require(len(by_cve) == 295 and all(x["approved_disposition"] is None
            for x in register["records"]), "unexpected or self-asserted register approval")
    exceptions = {}
    for row in d.get("cve_decisions", []):
        cve = row.get("cve")
        require(isinstance(cve, str) and CVE.fullmatch(cve) is not None
                and cve in by_cve, "unknown CVE in reviewer decision")
        require(cve not in exceptions, "duplicate CVE approval")
        require(row.get("status") == "not_affected"
                and row.get("justification") in ALLOWED,
                "unsupported VEX exception status or justification")
        require(len(row.get("review_reasoning") or "") >= 80
                and row.get("ubuntu_patch_review_reference")
                and row.get("indirect_uapi_abi_review_reference")
                and row.get("review_reference")
                and SHA.fullmatch(row.get("per_cve_evidence_sha256") or ""),
                "missing individual Ubuntu source/UAPI/ABI evidence")
        require(row.get("canonical_vendor_status") ==
                by_cve[cve]["canonical"]["status"], "vendor status changed by VEX")
        exceptions[cve] = row
    require(exceptions, "no CVE-specific approvals present")
    raw = findings(report)
    unresolved = []
    statements = []
    for (cve, pkg, version), finding in raw.items():
        row = exceptions.get(cve)
        if row is None or pkg != "linux-libc-dev" or version != "7.0.0-42.42":
            unresolved.append((cve, pkg, version))
            continue
        # A scanner match is scoped to the exact package, version, digest
        # and platform; never turn an unrelated package match into an exemption.
        statements.append({
            "vulnerability": {"name": cve},
            "products": [{"@id": image_purl}],
            "status": "not_affected", "justification": row["justification"],
            "impact_statement": row["review_reasoning"],
            "status_notes": "Independent decision " + d["decision_id"]
                + "; Canonical source status " + row["canonical_vendor_status"],
        })
    vex = {"@context": CONTEXT, "@id": "https://baobab.invalid/vex/"
           + d["decision_id"], "author": principal,
           "timestamp": d["issued_at"], "version": 1,
           "statements": statements}
    return vex, unresolved


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--raw-trivy", type=Path, required=True)
    p.add_argument("--signed-decision", type=Path, required=True)
    p.add_argument("--protected-trust", type=Path, required=True)
    p.add_argument("--register", type=Path, required=True)
    p.add_argument("--image-digest", required=True)
    p.add_argument("--platform", required=True)
    p.add_argument("--image-purl", required=True)
    p.add_argument("--openvex-output", type=Path, required=True)
    args = p.parse_args()
    try:
        load = lambda path: json.loads(path.read_text(encoding="utf-8"))
        vex, blocking = qualify(load(args.raw_trivy), load(args.signed_decision),
                                load(args.protected_trust),
                                image_digest=args.image_digest, platform=args.platform,
                                image_purl=args.image_purl, register=load(args.register))
        args.openvex_output.write_text(json.dumps(vex, indent=2, sort_keys=True) + "\n")
        if blocking:
            print("BLOCKED unapproved HIGH/CRITICAL findings:", len(blocking), file=sys.stderr)
            return 1
        print("All HIGH/CRITICAL findings reviewed; valid signed per-CVE scope")
        return 0
    except (PolicyError, ValueError, KeyError, OSError, subprocess.SubprocessError) as exc:
        print("SECURITY HELD:", str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
