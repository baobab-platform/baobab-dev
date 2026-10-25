"""Exercise the actual lifecycle script with controlled CLI processes."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/post-create.sh'


class PostCreateTests(unittest.TestCase):
    def run_case(self, files, *, fail='', pnpm='11.24.0'):
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
            for tool in ['uv','poetry','npm','pnpm','node']:
                body='#!/bin/sh\nprintf "%s\\n" "'+tool+' $*" >> "$TRACE"\n'
                if tool=='node':
                    body += "if [ \"$1\" = \"--version\" ]; then printf 'v24.21.0\\n'; else /usr/bin/python3 -c 'import json; print(json.load(open(\"package.json\")).get(\"packageManager\", \"\"))'; fi\n"
                elif tool=='pnpm':
                    body+='if [ "$1" = "--version" ]; then printf "%s\\n" "'+pnpm+'"; exit 0; fi\n'
                body+='[ "$FAIL_TOOL" != "'+tool+'" ]\n'
                (binpath/tool).write_text(body);(binpath/tool).chmod(0o755)
            env={**os.environ,'PATH':str(binpath)+':/usr/bin:/bin','WORKSPACE_DIR':str(root),
                 'TRACE':str(root/'trace'),'FAIL_TOOL':fail}
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
        files={'package.json':json.dumps({'packageManager':'pnpm@11.24.0'}),'pnpm-lock.yaml':''}
        r,t=self.run_case(files)
        self.assertEqual(0,r.returncode,r.stdout+r.stderr)
        self.assertIn('pnpm install --frozen-lockfile',t)
        r,t=self.run_case(files,pnpm='11.23.0')
        self.assertNotEqual(0,r.returncode)
        self.assertNotIn('pnpm install',t)

    def test_frontend_uses_same_frozen_failure_path(self):
        r,t=self.run_case({'frontend/package.json':'{}','frontend/package-lock.json':'{}'},fail='npm')
        self.assertNotEqual(0,r.returncode)
        self.assertNotIn('npm install',t)

    def test_conflicting_node_locks_and_wrong_node_pin_refused(self):
        for files in ({'package.json':'{}','package-lock.json':'','pnpm-lock.yaml':''},
                      {'package.json':'{}','package-lock.json':'','.node-version':'24.20.0'}):
            r,t=self.run_case(files)
            self.assertNotEqual(0,r.returncode)
            self.assertNotIn('npm ci',t)


if __name__=='__main__':
    unittest.main()
