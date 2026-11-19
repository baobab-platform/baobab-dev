"""One BuildKit layout supplies the native runtime, scanner and registry."""

import gzip
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import attested_release_layout as layout


SOURCE = "a" * 40
LOCK = "b" * 64


def create_layout(root):
    store = root / "blobs" / "sha256"
    store.mkdir(parents=True)

    def write(media_type, payload, **extras):
        if isinstance(payload, dict):
            payload = json.dumps(payload, separators=(",", ":")).encode()
        digest = hashlib.sha256(payload).hexdigest()
        (store / digest).write_bytes(payload)
        return {"mediaType": media_type, "digest": "sha256:" + digest, "size": len(payload), **extras}

    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as data:
        payload = b"native qualification probe"
        file = tarfile.TarInfo("probe.txt")
        file.size = len(payload)
        data.addfile(file, io.BytesIO(payload))
    layer = write("application/vnd.oci.image.layer.v1.tar+gzip", gzip.compress(stream.getvalue()))
    config = write(layout.CONFIG, {
        "architecture": "amd64", "os": "linux",
        "config": {"Env": ["BAOBAB_BUILD_PROFILE=full"],
                   "Labels": {"org.opencontainers.image.revision": SOURCE}},
        "rootfs": {"type": "layers", "diff_ids": ["sha256:" + hashlib.sha256(stream.getvalue()).hexdigest()]},
    })
    native = write(layout.MANIFEST, {"schemaVersion": 2, "mediaType": layout.MANIFEST,
                                    "config": config, "layers": [layer]},
                   platform={"os": "linux", "architecture": "amd64"})
    layers = [write("application/vnd.in-toto+json", {"predicateType": predicate},
                    annotations={"in-toto.io/predicate-type": predicate})
              for predicate in ("https://slsa.dev/provenance/v1", "https://spdx.dev/Document")]
    attestation = write(layout.MANIFEST, {"schemaVersion": 2, "mediaType": layout.MANIFEST,
                                         "config": config, "layers": layers},
                        platform={"os": "unknown", "architecture": "unknown"},
                        annotations={"vnd.docker.reference.type": "attestation-manifest",
                                     "vnd.docker.reference.digest": native["digest"]})
    index = write(layout.INDEX, {"schemaVersion": 2, "mediaType": layout.INDEX,
                                "manifests": [native, attestation]})
    (root / "index.json").write_text(json.dumps({"schemaVersion": 2, "manifests": [index]}))
    (root / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}')
    return index["digest"], layer["digest"]


class ReleaseLayoutTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.layout = Path(temporary.name) / "oci"
        self.archive = Path(temporary.name) / "native.tar"
        self.index, self.layer = create_layout(self.layout)

    def inspect(self, source=SOURCE):
        return layout.inspect(self.layout, "final", "amd64", source, LOCK, self.index)

    def test_archive_and_runtime_receipt_are_bound_to_the_same_native_bytes(self):
        plan, config, layers = self.inspect()
        layout.docker_archive(self.archive, self.layout, plan, config, layers)
        with tarfile.open(self.archive) as archived:
            paths = json.load(archived.extractfile("manifest.json"))[0]
            self.assertEqual(paths["RepoTags"], [layout.SCAN_TAG])
            index = json.load(archived.extractfile("index.json"))
            self.assertEqual(index["manifests"][0]["digest"], plan["child_digest"])
            raw_manifest = archived.extractfile("blobs/sha256/" + plan["child_digest"][7:]).read()
            self.assertEqual(hashlib.sha256(raw_manifest).hexdigest(), plan["child_digest"][7:])
            self.assertEqual(hashlib.sha256(archived.extractfile(paths["Config"]).read()).hexdigest(),
                             plan["config_digest"].removeprefix("sha256:"))
            self.assertEqual(hashlib.sha256(archived.extractfile(paths["Layers"][0]).read()).hexdigest(),
                             self.layer.removeprefix("sha256:"))
        scanner = {
            "SchemaVersion": 2, "ArtifactType": "container_image", "ArtifactName": str(self.archive),
            "Metadata": {"ImageID": plan["config_digest"],
                         "ImageConfig": {"os": "linux", "architecture": "amd64"}},
            "Results": [{"Target": "native-ubuntu", "Vulnerabilities": []}],
        }
        runtime = {"source_sha": SOURCE, "lock_sha256": LOCK, "platform": "linux/amd64",
                   "image_config_digest": plan["config_digest"], "image_engine_id": plan["child_digest"],
                   "profile": "full",
                   "scan_archive_sha256": layout.sha256(self.archive),
                   "health": "healthy", "runtime": "passed"}
        proof = layout.qualified(plan, runtime, scanner, self.archive, "0.73.0")
        self.assertEqual(proof["index_digest"], self.index)
        self.assertEqual(proof["security"], "unfiltered-clean")
        with self.assertRaisesRegex(ValueError, "runtime receipt"):
            layout.qualified(plan, dict(runtime, lock_sha256="c" * 64), scanner, self.archive, "0.73.0")
        scanner["Metadata"]["ImageID"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(ValueError, "exact native OCI child"):
            layout.qualified(plan, runtime, scanner, self.archive, "0.73.0")
        scanner["Metadata"]["ImageID"] = plan["config_digest"]
        scanner["Results"][0]["Vulnerabilities"].append({
            "Severity": "HIGH", "VulnerabilityID": "CVE-2026-1234",
            "PkgName": "probe", "InstalledVersion": "1.0",
        })
        with self.assertRaisesRegex(ValueError, "release authorization"):
            layout.qualified(plan, runtime, scanner, self.archive, "0.73.0")

    def test_hashes_paths_and_source_cannot_be_substituted(self):
        with self.assertRaisesRegex(ValueError, "source, platform or profile"):
            self.inspect(source="c" * 40)
        layer = self.layout / "blobs/sha256" / self.layer.removeprefix("sha256:")
        layer.write_bytes(b"x" * layer.stat().st_size)
        with self.assertRaisesRegex(ValueError, "bytes differ"):
            self.inspect()


if __name__ == "__main__":
    unittest.main()
