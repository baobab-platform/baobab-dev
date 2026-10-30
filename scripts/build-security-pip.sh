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
# pip intentionally strips msgpack's compiled extensions from its vendored tree.
# Pip's stock pkg_resources patch targets setuptools 70.3.0. After raising
# the vendored copy to the fixed 78.1.1, that patch no longer applies:
# new pkg_resources imports jaraco.text via a different path. Remove ONLY
# the incompatible upstream patch and apply its two semantic changes with
# strict source guards below. Other pip vendoring patches still apply.
test -f tools/vendoring/patches/pkg_resources.patch
grep -q 'pip._internal.utils._jaraco_text' tools/vendoring/patches/pkg_resources.patch
rm tools/vendoring/patches/pkg_resources.patch
MSGPACK_PUREPYTHON=1 vendoring sync
python - <<'PY'
from pathlib import Path

p = Path('src/pip/_vendor/pkg_resources/__init__.py')
s = p.read_text()
# pkg_resources 78.1.1 no longer uses pkg_resources.extern.jaraco.text.
# An unexpected import shape indicates upstream has changed: refuse.
candidates = (
    'from jaraco.text import drop_comment, join_continuation, yield_lines',
    'from pkg_resources.extern.jaraco.text import (\\n'
    '    yield_lines,\\n'
    '    drop_comment,\\n'
    '    join_continuation,\\n'
    ')',
)
hits = [source for source in candidates if s.count(source) == 1]
assert len(hits) == 1, 'PKG_RESOURCES_JARACO_IMPORT_DRIFT'
s = s.replace(
    hits[0],
    'from pip._internal.utils._jaraco_text import '
    'drop_comment, join_continuation, yield_lines',
)
warning = (
    'warnings.warn(\\n'
    '    "pkg_resources is deprecated as an API. "\\n'
    '    "See https://setuptools.pypa.io/en/latest/pkg_resources.html",\\n'
    '    DeprecationWarning,\\n'
    '    stacklevel=2,\\n'
    ')'
)
assert s.count(warning) == 1, 'PKG_RESOURCES_DEPRECATION_WARNING_DRIFT'
s = s.replace(warning, '# Vendored pkg_resources: omit deprecation warning (pip upstream policy).')
p.write_text(s)
PY
python -m pip wheel --no-build-isolation --no-deps . -w /out
python -m venv /build/check
/build/check/bin/python -m pip install --no-index --no-deps /out/pip-26.2.2+baobab.1-py3-none-any.whl
/build/check/bin/python - <<'PY'
import pip
from pip._vendor import urllib3, msgpack, setuptools
from pip._vendor.requests.adapters import HTTPAdapter
assert pip.__version__ == '26.2.2+baobab.1'
assert urllib3.__version__ == '2.8.0'
assert msgpack.version >= (1, 2, 3), f'VENDORED_MSGPACK_DRIFT: {msgpack.version}'
assert tuple(int(x) for x in setuptools.__version__.split('.')[:3]) >= (78, 1, 1), (
    f'VENDORED_SETUPTOOLS_DRIFT: {setuptools.__version__}'
)
assert HTTPAdapter().poolmanager.__class__ is urllib3.PoolManager
PY
/build/check/bin/python -m pip check
sha256sum /out/*.whl > /out/pip-wheel.sha256
