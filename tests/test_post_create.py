"""Exercise the actual lifecycle script with controlled CLI processes."""
import json
import os
import shutil
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/post-create.sh'


class PostCreateTests(unittest.TestCase):
    def run_case(self, files, *, fail='', pnpm='12.21.0', members='yes'):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'config').mkdir()
            (root/'config/versions.yaml').write_text('{}')
            (root/'config/versions.lock').write_text('export PYTHON_MINOR=3.14\n')
            (root/'config/resolve.sh').write_text('#!/bin/sh\nexit 99\n')
            (root/'config/resolve.sh').chmod(0o755)
            for name, data in files.items():
                p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(data)
            binpath=root/'bin';binpath.mkdir()
            for tool in ['uv','poetry','npm','pnpm','corepack','yarn','node']:
                body='#!/bin/sh\nprintf "%s\\n" "'+tool+' $*" >> "$TRACE"\n'
                if tool=='node':
                    body += """if [ "$1" = "--version" ]; then
  printf 'v26.13.1\\n'
elif [ "$1" = "-e" ]; then
  exec "$REAL_NODE" "$@"
else
  /usr/bin/python3 -c 'import json; print(json.load(open("package.json")).get("packageManager", ""))'
fi
"""
                elif tool=='corepack':
                    body += """if [ "$1" = "install" ]; then
  [ "$COREPACK_HOME" = "$PROJECT_COREPACK_HOME_EXPECTED" ] || exit 41
  [ -d "$COREPACK_HOME" ] || exit 42
  [ "$COREPACK_ENABLE_NETWORK" = "1" ] || exit 43
  [ "$COREPACK_ON_UNVERIFIED_DOWNLOAD" = "error" ] || exit 44
  [ "$COREPACK_ENABLE_DOWNLOAD_PROMPT" = "0" ] || exit 45
  [ -z "${COREPACK_INTEGRITY_KEYS+x}" ] || exit 46
  [ "$FAIL_TOOL" != "corepack" ] || exit 47
  : > "$COREPACK_HOME/package-manager-ready"
  exit 0
fi
if [ "$1" = "pnpm" ]; then
  shift
  [ "$COREPACK_HOME" = "$PROJECT_COREPACK_HOME_EXPECTED" ] || exit 48
  [ -d "$COREPACK_HOME" ] || exit 49
  [ "$COREPACK_ON_UNVERIFIED_DOWNLOAD" = "error" ] || exit 51
  [ "$COREPACK_ENABLE_DOWNLOAD_PROMPT" = "0" ] || exit 52
  [ -z "${COREPACK_INTEGRITY_KEYS+x}" ] || exit 53
  if [ "$1" = "--version" ]; then
    [ -f "$COREPACK_HOME/package-manager-ready" ] || exit 54
    if [ "$COREPACK_ENABLE_NETWORK" = "1" ]; then
      : > "$COREPACK_HOME/native-binary-ready"
    elif [ "$COREPACK_ENABLE_NETWORK" = "0" ]; then
      [ -f "$COREPACK_HOME/native-binary-ready" ] || exit 55
    else
      exit 56
    fi
    printf '%s\\n' 'VERSION_PIN'
    exit 0
  fi
  if [ "$1" = "install" ]; then
    [ "$COREPACK_ENABLE_NETWORK" = "0" ] || exit 57
    [ -f "$COREPACK_HOME/native-binary-ready" ] || exit 58
    exit 0
  fi
  if [ "$1" = "list" ]; then
    [ "$COREPACK_ENABLE_NETWORK" = "0" ] || exit 59
    [ -f "$COREPACK_HOME/native-binary-ready" ] || exit 60
    if [ "$PNPM_MEMBERS" = "yes" ]; then
      printf '[{"path":"%s/frontend"}]\\n' "$WORKSPACE_DIR"
    else
      printf '[{"path":"%s"}]\\n' "$WORKSPACE_DIR"
    fi
    exit 0
  fi
fi
exit 54
""".replace("VERSION_PIN", pnpm)
                elif tool=='yarn':
                    body += """[ "$COREPACK_HOME" = "$IMAGE_COREPACK_HOME_EXPECTED" ] || exit 55
[ "$COREPACK_ENABLE_NETWORK" = "0" ] || exit 56
if [ "$1" = "--version" ]; then
  printf '4.18.1\\n'
  exit 0
fi
"""
                body+='[ "$FAIL_TOOL" != "'+tool+'" ]\n'
                (binpath/tool).write_text(body);(binpath/tool).chmod(0o755)
            project_corepack_home = root/'home'/'.cache'/'baobab-corepack'
            env={**os.environ,'PATH':str(binpath)+':/usr/bin:/bin','WORKSPACE_DIR':str(root),
                 'HOME':str(root/'home'),
                 'COREPACK_HOME':'/usr/local/share/baobab/corepack',
                 'COREPACK_ENABLE_NETWORK':'0','COREPACK_ENABLE_DOWNLOAD_PROMPT':'0',
                 'COREPACK_INTEGRITY_KEYS':'0',
                 'BAOBAB_COREPACK_PROJECT_HOME':str(project_corepack_home),
                 'PROJECT_COREPACK_HOME_EXPECTED':str(project_corepack_home),
                 'IMAGE_COREPACK_HOME_EXPECTED':'/usr/local/share/baobab/corepack',
                 'TRACE':str(root/'trace'),'FAIL_TOOL':fail,'PNPM_MEMBERS':members,
                 'REAL_NODE':shutil.which('node') or '/usr/bin/node'}
            result=subprocess.run(['bash',str(SCRIPT),'--stage=post-create'],cwd=root,env=env,
                                  capture_output=True,text=True)
            trace=(root/'trace').read_text() if (root/'trace').exists() else ''
            return result,trace

    def test_uv_project_never_uses_poetry_or_resolves_new_lock(self):
        r,t=self.run_case({'pyproject.toml':'[project]','uv.lock':'version=1'})
        self.assertEqual(0,r.returncode,r.stdout+r.stderr)
        self.assertIn('uv sync --locked --no-managed-python',t)
        self.assertNotIn('poetry ',t)

    def test_uv_failure_is_not_a_successful_onboarding(self):
        r,t=self.run_case({'pyproject.toml':'[project]','uv.lock':'version=1'},fail='uv')
        self.assertNotEqual(0,r.returncode)
        self.assertNotIn('poetry ',t)

    def test_python_ambiguous_or_missing_lock_is_refused(self):
        for files in ({'pyproject.toml':''},{'pyproject.toml':'','uv.lock':'','poetry.lock':''}):
            r,t=self.run_case(files)
            self.assertNotEqual(0,r.returncode)
            self.assertNotIn(' install',t)

    def test_npm_failure_never_falls_back_to_unlocked_install(self):
        r,t=self.run_case({'package.json':'{}','package-lock.json':'{}'},fail='npm')
        self.assertNotEqual(0,r.returncode)
        self.assertEqual(['npm ci'],[line for line in t.splitlines() if line.startswith('npm ')])

    def test_missing_npm_lock_is_refused(self):
        r,t=self.run_case({'package.json':'{}'})
        self.assertNotEqual(0,r.returncode)
        self.assertNotIn('npm install',t)

    def test_pnpm_exact_project_pin_and_frozen_install(self):
        for version in ('12.21.0', '12.16.1', '11.24.0'):
            with self.subTest(version=version):
                files={'package.json':json.dumps({'packageManager':f'pnpm@{version}'}),'pnpm-lock.yaml':''}
                r,t=self.run_case(files,pnpm=version)
                self.assertEqual(0,r.returncode,r.stdout+r.stderr)
                self.assertIn('corepack install',t)
                self.assertIn('corepack pnpm install --frozen-lockfile',t)
                self.assertFalse(any(line.startswith('pnpm ') for line in t.splitlines()))
        files={'package.json':json.dumps({'packageManager':'pnpm@12.21.0'}),'pnpm-lock.yaml':''}
        r,t=self.run_case(files,pnpm='12.20.0')
        self.assertNotEqual(0,r.returncode)
        self.assertNotIn('corepack pnpm install --frozen-lockfile',t)

    def test_frontend_uses_same_frozen_failure_path(self):
        r,t=self.run_case({'frontend/package.json':'{}','frontend/package-lock.json':'{}'},fail='npm')
        self.assertNotEqual(0,r.returncode)
        self.assertNotIn('npm install',t)

    def test_yarn_uses_the_preloaded_image_corepack_cache(self):
        files = {
            'package.json': json.dumps({'packageManager': 'yarn@4.18.1'}),
            'yarn.lock': '# yarn lockfile',
        }
        r, trace = self.run_case(files)
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)
        self.assertIn('yarn install --immutable', trace)
        self.assertNotIn('corepack install', trace)

    def test_corepack_prepare_failure_never_falls_back_to_native_pnpm(self):
        files = {
            'package.json': json.dumps({'packageManager': 'pnpm@12.21.0'}),
            'pnpm-lock.yaml': '',
        }
        r, trace = self.run_case(files, fail='corepack')
        self.assertNotEqual(0, r.returncode)
        self.assertNotIn('corepack pnpm install --frozen-lockfile', trace)
        self.assertNotIn('pnpm install --frozen-lockfile', trace)

    def test_root_pnpm_workspace_requires_declared_frontend_membership(self):
        files = {
            'package.json': json.dumps({'packageManager': 'pnpm@12.21.0'}),
            'pnpm-workspace.yaml': 'packages:\n  - packages/*\n',
            'pnpm-lock.yaml': 'lockfileVersion: 9.0\n',
            'frontend/package.json': json.dumps({'name': 'frontend'}),
        }
        r, trace = self.run_case(files, members='no')
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('not a declared member', r.stderr)
        self.assertIn('corepack pnpm list -r --depth -1 --json', trace)
        self.assertNotIn('npm ci', trace)
        self.assertEqual(1, trace.count('corepack pnpm install --frozen-lockfile'))
        r, trace = self.run_case(files, members='yes')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('Frontend covered by the root frozen pnpm workspace lock', r.stdout)
        self.assertEqual(1, trace.count('corepack pnpm install --frozen-lockfile'))

    def test_root_pnpm_workspace_without_lock_fails_closed(self):
        r, trace = self.run_case({
            'package.json': json.dumps({'packageManager': 'pnpm@11.24.0'}),
            'pnpm-workspace.yaml': 'packages:\n  - frontend\n',
            'package-lock.json': '{}',
            'frontend/package.json': '{}',
        })
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn('npm ci', trace)

    def test_conflicting_node_locks_and_wrong_node_pin_refused(self):
        for files in ({'package.json':'{}','package-lock.json':'','pnpm-lock.yaml':''},
                      {'package.json':'{}','package-lock.json':'','.node-version':'26.13.0'}):
            r,t=self.run_case(files)
            self.assertNotEqual(0,r.returncode)
            self.assertNotIn('npm ci',t)


if __name__=='__main__':
    unittest.main()
