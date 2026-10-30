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
assert s.count('urllib3==2.7.0') == 1, 'UPSTREAM_VENDOR_DRIFT'
p.write_text(s.replace('urllib3==2.7.0', 'urllib3==2.8.0'))
p = Path('src/pip/__init__.py')
s = p.read_text()
assert s.count('__version__ = "26.2.2"') == 1, 'UPSTREAM_PIP_VERSION_DRIFT'
p.write_text(s.replace('__version__ = "26.2.2"', '__version__ = "26.2.2+baobab.1"'))
PY
# pip intentionally strips msgpack's compiled extensions from its vendored tree.
MSGPACK_PUREPYTHON=1 vendoring sync
python -m pip wheel --no-build-isolation --no-deps . -w /out
python -m venv /build/check
/build/check/bin/python -m pip install --no-index --no-deps /out/pip-26.2.2+baobab.1-py3-none-any.whl
/build/check/bin/python - <<'PY'
import pip
from pip._vendor import urllib3
from pip._vendor.requests.adapters import HTTPAdapter
assert pip.__version__ == '26.2.2+baobab.1'
assert urllib3.__version__ == '2.8.0'
assert HTTPAdapter().poolmanager.__class__ is urllib3.PoolManager
PY
/build/check/bin/python -m pip check
sha256sum /out/*.whl > /out/pip-wheel.sha256
