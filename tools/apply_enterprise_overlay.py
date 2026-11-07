"""Preview/apply Day37 enterprise overlay to the reviewed Feature Branch.

No GitHub write, AWS operation, Terraform Apply, IAM changes or network access.
Refuses mismatched commit, dirty protected files and unknown upstream contracts.
"""
from __future__ import annotations
import argparse
import hashlib
import shutil
import subprocess
from pathlib import Path
import yaml

REVIEWED_SHA = 'b1816954c7242417cd60880c94f182eb6b2357c6'
REQUIRED_BASE = ('scripts/day37_gate.py','scripts/day37_aws.py','scripts/day37_plan_transport.py',
                 'scripts/day37_preflight.py','scripts/day37_tf.sh',
                 '.github/workflows/day37-reconcile.yml',
                 'infra/terraform/environments/ota-staging-foundation/main.tf')
OVERLAY = ['.github/workflows/day37-aws-staging.yml', '.github/workflows/day37-bootstrap-reconcile.yml']
OVERLAY += [str(p.relative_to(Path(__file__).resolve().parents[1])) for base in ('scripts','tests/unit','docs')
            for p in sorted(((Path(__file__).resolve().parents[1])/base).glob('*')) if p.is_file()]
OVERLAY += ['tools/patch_foundation.py','tools/patch_existing_manual_recovery.py',
            'tools/apply_enterprise_overlay.py','tools/patch_existing_day37_tests.py']


def cmd(*arguments: str, cwd: Path) -> str:
    p=subprocess.run(list(arguments),cwd=cwd,capture_output=True,text=True,timeout=12)
    if p.returncode:raise ValueError('BLOCKED: git prerequisite refused: '+' '.join(arguments[:3]))
    return p.stdout.strip()


def prepare(repo: Path, source: Path, reviewed_sha: str) -> dict[str,bytes]:
    assert (repo/'.git').exists(), 'not a Git worktree'
    actual=cmd('git','rev-parse','HEAD',cwd=repo)
    if actual != reviewed_sha:raise ValueError(f'BLOCKED: branch HEAD {actual} not reviewed {reviewed_sha}')
    for path in REQUIRED_BASE:
        if not (repo/path).is_file():raise ValueError('BLOCKED: missing actual repository dependency '+path)
    protected=[*REQUIRED_BASE,'.github/workflows/day37-aws-staging.yml']
    dirty=cmd('git','status','--porcelain','--',*protected,cwd=repo)
    if dirty:raise ValueError('BLOCKED: target has unreviewed local edits: '+dirty[:200])
    from importlib.util import spec_from_file_location, module_from_spec
    def load_py(name,filename):
        spec=spec_from_file_location(name,source/'tools'/filename)
        mod=module_from_spec(spec);spec.loader.exec_module(mod)
        return mod
    foundation=load_py('patch_foundation','patch_foundation.py')
    manual=load_py('patch_manual','patch_existing_manual_recovery.py')
    modified={p:(source/p).read_bytes() for p in OVERLAY}
    manual_yml=manual.patch_manual((repo/'.github/workflows/day37-reconcile.yml').read_text())
    foundation_hcl=foundation.patch((repo/'infra/terraform/environments/ota-staging-foundation/main.tf').read_text())
    modified['.github/workflows/day37-reconcile.yml']=manual_yml.encode()
    modified['infra/terraform/environments/ota-staging-foundation/main.tf']=foundation_hcl.encode()
    tests=load_py('patch_original_tests','patch_existing_day37_tests.py')
    for path,patcher in tests.FILES.items():
        if not (repo/path).is_file():
            raise ValueError('BLOCKED: original Day37 test missing '+path)
        modified[path]=patcher((repo/path).read_text()).encode()
    for path in ('.github/workflows/day37-aws-staging.yml','.github/workflows/day37-bootstrap-reconcile.yml','.github/workflows/day37-reconcile.yml'):
        document=yaml.safe_load(modified[path]);
        if not isinstance(document,dict) or 'jobs' not in document or 'on' not in document:
            raise ValueError('BLOCKED: invalid combined workflow '+path)
    return modified


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--repo',type=Path,default=Path('.'))
    p.add_argument('--source',type=Path,default=Path(__file__).resolve().parents[1])
    p.add_argument('--expect-sha',default=REVIEWED_SHA)
    p.add_argument('--preview-dir',type=Path,default=Path('.day37/enterprise-preview'))
    p.add_argument('--apply',action='store_true')
    args=p.parse_args()
    repo=args.repo.resolve();source=args.source.resolve()
    prepared=prepare(repo,source,args.expect_sha)
    for name,content in sorted(prepared.items()):
        dst=(repo if args.apply else args.preview_dir.resolve())/name
        dst.parent.mkdir(parents=True,exist_ok=True)
        if dst.exists() and dst.is_symlink():raise ValueError('BLOCKED: target symlink '+str(dst))
        dst.write_bytes(content)
        print(('APPLIED' if args.apply else 'PREVIEW'),name,hashlib.sha256(content).hexdigest()[:12])
    print('DONE: no AWS/GitHub/Terraform operations were invoked')

if __name__=='__main__':
    main()
