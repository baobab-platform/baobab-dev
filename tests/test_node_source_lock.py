"""Regression: NodeSource release drift must fail before costly image layers.

The exact Node binary and apt package are governed by config/versions.yaml,
not a floating major-series NodeSource installation.
"""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def test_node_source_manifest_lock_agree() -> None:
    manifest = (ROOT / "config/versions.yaml").read_text()
    lock = (ROOT / "config/versions.lock").read_text()
    node = re.search(r"(?m)^    exact: \"(\d+\.\d+\.\d+)\"$", manifest)
    assert node, "Node version manifest must carry an exact release"
    assert f"export NODE_VERSION={node.group(1)}\n" in lock


def test_nodesource_apt_package_is_exact_and_preflighted() -> None:
    dockerfile = (ROOT / ".devcontainer/docker/Dockerfile").read_text()
    assert 'apt-cache policy nodejs' in dockerfile
    assert 'test "${NODE_CANDIDATE}" = "${NODE_VERSION}-1nodesource1"' in dockerfile
    assert '"nodejs=${NODE_VERSION}-1nodesource1"' in dockerfile
    assert 'test "$(node --version)" = "v${NODE_VERSION}"' in dockerfile
    assert 'libatomic1 nodejs &&' not in dockerfile
