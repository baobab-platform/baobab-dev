#!/usr/bin/env bash
# Re-vendor through pip's own documented tool; never patch version metadata alone.
set -euo pipefail
curl -fsSL --retry 5 --retry-all-errors \
  https://api.github.com/repos/pypa/pip/tarball/26.2.2 -o /build/pip.tar.gz
echo '56cb05f56b5218ba7a61559edeac52a56419411fff8ff9efeceadd8a1fd6bd61  /build/pip.tar.gz' | sha256sum --check --strict
mkdir /build/pip
tar -xzf /build/pip.tar.gz -C /build/pip --strip-components=1
cd /build/pip
python - <<'PY'
from pathlib import Path
p = Path('src/pip/_vendor/vendor.txt')
s = p.read_text()
replacements = {
    'urllib3==2.7.0': 'urllib3==2.8.0',
    'msgpack==1.1.2': 'msgpack==1.2.3',
    'setuptools==70.3.0': 'setuptools==78.1.1',
}
for old, new in replacements.items():
    assert s.count(old) == 1, f'UPSTREAM_VENDOR_DRIFT: {old}'
    s = s.replace(old, new)
p.write_text(s)
p = Path('src/pip/__init__.py')
s = p.read_text()
assert s.count('__version__ = "26.2.2"') == 1, 'UPSTREAM_PIP_VERSION_DRIFT'
p.write_text(s.replace('__version__ = "26.2.2"', '__version__ = "26.2.2+baobab.1"'))
PY
# Pip's original pkg_resources patch assumed setuptools 70.3.0.
# Pip vendoring refuses dotted imports in setuptools 78.1.1, so replace
# ONLY that patch with an audited 78.1.1-compatible version. Import rewriting
# still runs through the upstream vendoring tool; no security controls skipped.
test -f tools/vendoring/patches/pkg_resources.patch
grep -q 'pip._internal.utils._jaraco_text' tools/vendoring/patches/pkg_resources.patch
cat > tools/vendoring/patches/pkg_resources.patch <<'PKG_RESOURCES_78_PATCH'
diff --git a/src/pip/_vendor/pkg_resources/__init__.py b/src/pip/_vendor/pkg_resources/__init__.py
--- a/src/pip/_vendor/pkg_resources/__init__.py
+++ b/src/pip/_vendor/pkg_resources/__init__.py
@@ -82,12 +82,9 @@
     # no write support, probably under GAE
     WRITE_SUPPORT = False
 
-import packaging.markers
-import packaging.requirements
-import packaging.specifiers
-import packaging.utils
-import packaging.version
-from jaraco.text import drop_comment, join_continuation, yield_lines
+import packaging
+from packaging import markers, requirements, specifiers, utils, version
+from pip._internal.utils._jaraco_text import drop_comment, join_continuation, yield_lines
 from platformdirs import user_cache_dir as _user_cache_dir
 
 if TYPE_CHECKING:
@@ -95,12 +92,7 @@
     from _typeshed.importlib import LoaderProtocol
     from typing_extensions import Self, TypeAlias
 
-warnings.warn(
-    "pkg_resources is deprecated as an API. "
-    "See https://setuptools.pypa.io/en/latest/pkg_resources.html",
-    DeprecationWarning,
-    stacklevel=2,
-)
+# As in pip's upstream patch, do not emit the vendored deprecation warning.
 
 _T = TypeVar("_T")
 _DistributionT = TypeVar("_DistributionT", bound="Distribution")
PKG_RESOURCES_78_PATCH
MSGPACK_PUREPYTHON=1 vendoring sync
python - <<'PY'
from pathlib import Path
p = Path('src/pip/_vendor/pkg_resources/__init__.py')
s = p.read_text()
assert 'pip._internal.utils._jaraco_text' in s, 'PKG_RESOURCES_JARACO_PATCH_MISSING'
assert 'warnings.warn(\\n    "pkg_resources is deprecated as an API.' not in s, 'PKG_RESOURCES_DEPRECATION_PATCH_MISSING'
assert 'import packaging.markers' not in s, 'PKG_RESOURCES_DOTTED_IMPORT_DRIFT'
PY
python -m pip wheel --no-build-isolation --no-deps . -w /out
python -m venv /build/check
/build/check/bin/python -m pip install --no-index --no-deps /out/pip-26.2.2+baobab.1-py3-none-any.whl
/build/check/bin/python - <<'PY'
import pip
from pip._vendor import urllib3, msgpack, pkg_resources
from pip._vendor.requests.adapters import HTTPAdapter
assert pip.__version__ == '26.2.2+baobab.1'
assert urllib3.__version__ == '2.8.0'
assert msgpack.version >= (1, 2, 3), f'VENDORED_MSGPACK_DRIFT: {msgpack.version}'
# pip vendors pkg_resources FROM setuptools, not setuptools itself.
# Strict source version is pinned above in vendor.txt; exercise real API here.
assert str(pkg_resources.parse_version('1.2.3')) == '1.2.3'
assert HTTPAdapter().poolmanager.__class__ is urllib3.PoolManager
PY
/build/check/bin/python -m pip check
sha256sum /out/*.whl > /out/pip-wheel.sha256
