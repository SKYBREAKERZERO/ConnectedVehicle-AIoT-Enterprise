"""Deterministically harden the user-supplied Day37 workflow; no AWS mutation."""
from __future__ import annotations
import argparse
from pathlib import Path
import yaml

DEF_RUN='''set -euo pipefail
umask 077
mkdir -p .day37/bootstrap-close
bash scripts/day37_tf.sh init
python -m scripts.day37_fence recovery-check --checkpoint /dev/null --fence /dev/null >/dev/null 2>&1 && { echo 'BLOCKED: forbidden synthetic checkpoint' >&2; exit 1; } || true
# A real S3 CAS readback is enforced inside the close command.
export TF_VAR_enable_service=false TF_VAR_desired_count=0
set +e
terraform -chdir="${DAY37_TF_ROOT}" plan -detailed-exitcode -input=false -lock-timeout=30s -no-color -out="${PWD}/.day37/bootstrap-close/no-drift.tfplan" > .day37/bootstrap-close/terraform-private.log 2>&1
RC=$?
set -e
[[ "$RC" -eq 0 ]] || { echo 'BLOCKED: Bootstrap still has Terraform drift' >&2; exit 1; }
terraform -chdir="${DAY37_TF_ROOT}" show -json "${PWD}/.day37/bootstrap-close/no-drift.tfplan" > .day37/bootstrap-close/no-drift.json
python -m scripts.day37_reconcile --phase bootstrap --fence .day37/bootstrap/fence.json --terraform-json .day37/bootstrap-close/no-drift.json --terraform-exit-code "$RC" --output .day37/bootstrap-close/proof.json
python -m scripts.day37_fence close --receipt .day37/bootstrap/fence.json --proof .day37/bootstrap-close/proof.json --output .day37/bootstrap-close/closed-fence.json
'''
# NOTE: NO artificial check commands should be part of production workflows.
DEF_RUN=DEF_RUN.replace("python -m scripts.day37_fence recovery-check --checkpoint /dev/null --fence /dev/null >/dev/null 2>&1 && { echo 'BLOCKED: forbidden synthetic checkpoint' >&2; exit 1; } || true\n", "")

SETUP_RUNTIME={'uses':'./.github/actions/setup-ci-runtime'}
CHECKOUT='actions/checkout@11d5960a326750d5838078e36cf38b85af677262'
DOWNLOAD='actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093'
UPLOAD='actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02'

def stage_step(job,needle):
    xs=[x for x in job['steps'] if needle in x.get('name','')]
    assert len(xs)==1,(needle,len(xs));return xs[0]

def setup_runtime(job):
    if not any(x.get('uses')==SETUP_RUNTIME['uses'] for x in job['steps']):
        ix=next(i for i,x in enumerate(job['steps']) if x.get('uses','').startswith('actions/setup-python@'))
        job['steps'].insert(ix+1,dict(SETUP_RUNTIME))

def modify(d):
    jobs=d['jobs']; assert len(jobs)==11
    source=stage_step(jobs['source'],'Python, evidence policy')
    source['run']=source['run'].replace('scripts/day37_release_guard.py', 'scripts/day37_release_guard.py scripts/day37_fence.py scripts/day37_reconcile.py scripts/day37_manual_proof.py scripts/day37_bootstrap_manual.py scripts/day37_enterprise_gate.py')
    source['run']=source['run'].replace('tests/unit/test_day37_preflight.py -q', 'tests/unit/test_day37_preflight.py tests/unit/test_day37_fence.py tests/unit/test_day37_release_guard_p0.py tests/unit/test_day37_reconcile_p0.py tests/unit/test_day37_manual_proof.py tests/unit/test_day37_bootstrap_manual.py tests/unit/test_day37_enterprise_gate.py -q')
    for key in ['plan','bootstrap','deploy_plan','deploy','close','recovery']:
        setup_runtime(jobs[key])
    plan=stage_step(jobs['plan'],'Read-only audit or bootstrap Plan')
    x=plan['run']; x=x.replace('set -euo pipefail\n','set -euo pipefail\numask 077\n',1)
    assert x.count('else\n  python -m scripts.day37_plan_transport clear-check')==1
    x=x.replace('else\n  python -m scripts.day37_plan_transport clear-check','elif [[ "${DAY37_MODE}" == "bootstrap" ]]; then\n  python -m scripts.day37_plan_transport clear-check',1)
    x=x.replace('        fi\n# Sensitive', '        else\n          echo "BLOCKED: invalid plan mode" >&2\n          exit 1\n        fi\n# Sensitive') if '        fi\n# Sensitive' in x else x.replace('fi\n# Sensitive', 'else\n  echo "BLOCKED: invalid plan mode" >&2\n  exit 1\nfi\n# Sensitive')
    # PyYAML block scalar indentation normalized; assert valid after write.
    plan['run']=x
    bootstrap=jobs['bootstrap']; bs=stage_step(bootstrap,'Fetch versioned approved Plan')
    x=bs['run'].replace('set -euo pipefail\n','set -euo pipefail\numask 077\n',1)
    old='python -m scripts.day37_plan_transport mark-fence --phase bootstrap --receipt .day37/reviewed-plan/receipt.json --output .day37/bootstrap/fence.json'
    assert old in x
    x=x.replace(old,'python -m scripts.day37_fence mark --phase bootstrap --receipt .day37/reviewed-plan/receipt.json --summary .day37/reviewed-plan/plan-summary.json --output .day37/bootstrap/fence.json')
    x=x[:x.index('python -m scripts.day37_aws bootstrap-verify --output')]+'python -m scripts.day37_aws bootstrap-verify --output .day37/bootstrap/bootstrap.json\n'
    bs['run']=x
    # Keep only two evidence uploads: success (bootstrap.json + fence.json) and failed fence.
    bootstrap['steps']=[s for s in bootstrap['steps'] if not (s.get('with',{}).get('name','').startswith('day37-bootstrap-failed-'))]
    # No bootstrap close in same AWS Apply identity.
    close=jobs['close'];cp=close['env'].copy()
    cp['DAY37_ROLE_ARN']='${{ vars.DAY37_RECOVERY_ROLE_ARN }}'
    cp['TF_VAR_enable_service']='false'
    cp['TF_VAR_desired_count']='0'
    cp.pop('DAY37_APPROVED_CONFIG_SHA',None)
    jobs['bootstrap_close']={
      'name':'03c Independent Bootstrap AWS/State reconcile and S3 CAS closure',
      'needs':['source','admission','plan','bootstrap'],
      'if':"${{ github.event_name == 'workflow_dispatch' && inputs.mode == 'bootstrap' && needs.bootstrap.result == 'success' }}",
      'environment':'aws-staging-recovery',
      'runs-on':'ubuntu-24.04',
      'timeout-minutes':30,
      'permissions':{'contents':'read','id-token':'write'},
      'env':cp,
      'steps':[
        {'uses':CHECKOUT,'with':{'persist-credentials':False}},
        {'uses':'actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065','with':{'python-version':'3.12'}},
        dict(SETUP_RUNTIME),
        {'uses':'hashicorp/setup-terraform@b9cd54a3c349d3f38e8881555d616ced269862dd','with':{'terraform_version':'1.14.7','terraform_wrapper':False}},
        {'name':'Validate independent recovery account and IAM role','run':'python -m scripts.day37_preflight config --mode recovery'},
        {'uses':'aws-actions/configure-aws-credentials@e1253824e5c10ff9df46874f81ed3ec929e19cfd','with':{'aws-region':'ap-northeast-1','role-to-assume':'${{ env.DAY37_ROLE_ARN }}','role-session-name':'day37-bootstrap-close-${{ github.run_id }}-${{ github.run_attempt }}','role-duration-seconds':1800}},
        {'name':'Verify Recovery Role and Staging prerequisites','run':'python -m scripts.day37_preflight live --mode recovery'},
        {'uses':DOWNLOAD,'with':{'name':'day37-bootstrap-${{ github.run_id }}-${{ github.run_attempt }}','path':'.day37/bootstrap'}},
        {'name':'Independent Bootstrap Zero Drift, AWS Recheck and Fence CAS','run':DEF_RUN},
        {'if':'${{ always() }}','uses':UPLOAD,'with':{'name':'day37-bootstrap-closure-${{ github.run_id }}-${{ github.run_attempt }}','path':'.day37/bootstrap-close/proof.json\n.day37/bootstrap-close/closed-fence.json','if-no-files-found':'warn','include-hidden-files':True,'retention-days':30}}
      ]}
    # Deploy stage real fence, not old transport lock that would incorrectly treat bootstrap as invalid.
    deploy=stage_step(jobs['deploy'],'Verify reviewed S3 Plan hash, mark reconciliation fence')
    x=deploy['run'].replace('set -euo pipefail\n','set -euo pipefail\numask 077\n',1)
    x=x.replace('python -m scripts.day37_plan_transport mark-fence --phase deploy --receipt .day37/reviewed-plan/receipt.json --output .day37/deploy/fence.json','python -m scripts.day37_fence mark --phase deploy --receipt .day37/reviewed-plan/receipt.json --summary .day37/reviewed-plan/plan-summary.json --release .day37/publish/release.json --checkpoint .day37/deploy/checkpoint.json --output .day37/deploy/fence.json')
    x=x.replace('--sha256 "$DAY37_APPROVED_PLAN_SHA" --release .day37/publish/release.json\n', '--sha256 "$DAY37_APPROVED_PLAN_SHA" --release .day37/publish/release.json --checkpoint .day37/deploy/checkpoint.json\n')
    deploy['run']=x
    # Deploy live reconciliation proof is independent of deployment & verification jobs.
    close=stage_step(jobs['close'],'Require real ECS Digest and ZERO changes')
    x=close['run']; x=x.replace('set -euo pipefail\n','set -euo pipefail\numask 077\n',1)
    x=x.replace('python -m scripts.day37_release_guard closure --receipt .day37/fence/fence.json --summary .day37/verified/verified.json --sha256 "$DAY37_APPROVED_PLAN_SHA" --release .day37/publish/release.json\npython -m scripts.day37_plan_transport close-fence --receipt .day37/fence/fence.json --verified','''terraform -chdir="${DAY37_TF_ROOT}" show -json "${PWD}/.day37/closure/zero-drift.tfplan" > .day37/closure/zero-drift.json
python -m scripts.day37_reconcile --phase deploy --fence .day37/fence/fence.json --terraform-json .day37/closure/zero-drift.json --terraform-exit-code "$CODE" --release .day37/publish/release.json --output .day37/closure/proof.json
python -m scripts.day37_release_guard closure --receipt .day37/fence/fence.json --proof .day37/closure/proof.json --sha256 "$DAY37_APPROVED_PLAN_SHA" --release .day37/publish/release.json
python -m scripts.day37_fence close --receipt .day37/fence/fence.json --proof .day37/closure/proof.json --output .day37/closure/fence-closed.json''')
    assert 'day37_plan_transport close-fence' not in x
    close['run']=x
    close_upload=next(s for s in jobs['close']['steps'] if s.get('with',{}).get('name','').startswith('day37-closure-'))
    close_upload['with']['path']='.day37/closure/closed.json\n.day37/closure/proof.json\n.day37/closure/fence-closed.json'
    # Recovery requires authenticated LIVE fence + checkpoint matching; never use static artifact alone.
    rec=jobs['recovery']; anchor=stage_step(rec,'Revert ECS only after checkpoint')
    anchor['run']='''set -euo pipefail
python -m scripts.day37_fence recovery-check --checkpoint .day37/recovery/checkpoint.json --fence .day37/recovery/fence/fence.json
python -m scripts.day37_release_guard recovery-admission --checkpoint .day37/recovery/checkpoint.json --fence .day37/recovery/fence/fence.json
python -m scripts.day37_aws recover --checkpoint .day37/recovery/checkpoint.json --output .day37/recovery/recovery.json'''
    ix=rec['steps'].index(anchor)
    rec['steps'].insert(ix,{'if':"${{ steps.checkpoint.outputs.exists == 'true' }}",'uses':DOWNLOAD,'with':{'name':'day37-fence-${{ github.run_id }}-${{ github.run_attempt }}','path':'.day37/recovery/fence'}})
    # Reject zero-evidence final; original gate expects old 10 jobs, adapter does its own DAG validation.
    gate=jobs['gate']
    gate['needs'].insert(gate['needs'].index('bootstrap')+1,'bootstrap_close')
    up=next(s for s in gate['steps'] if s.get('with',{}).get('name','').startswith('day37-bootstrap-${{'))
    gate['steps'].insert(gate['steps'].index(up)+1,{'if':"${{ inputs.mode == 'bootstrap' && needs.bootstrap_close.result == 'success' }}",'uses':DOWNLOAD,'with':{'name':'day37-bootstrap-closure-${{ github.run_id }}-${{ github.run_attempt }}','path':'.day37/check/bootstrap'}})
    fs=stage_step(gate,'Emit evidence-bound READY/BLOCKED')
    fs['run']='''set -euo pipefail
umask 077
mkdir -p .day37
python -m scripts.day37_enterprise_gate --mode "${DAY37_MODE}" --folder .day37/check --output .day37/final.json'''
    # Plan, Bootstrap and Deploy jobs must never run from pull_request; existing conditions preserved.
    assert len(jobs)==12
    return d

def main():
 p=argparse.ArgumentParser();p.add_argument('--source',required=True);p.add_argument('--output',required=True)
 a=p.parse_args()
 d=yaml.safe_load(Path(a.source).read_text(encoding='utf-8'))
 out=modify(d)
 text=yaml.safe_dump(out,sort_keys=False,allow_unicode=True,width=140)
 Path(a.output).parent.mkdir(parents=True,exist_ok=True)
 Path(a.output).write_text(text,encoding='utf-8')
 print('WROTE',a.output,'jobs:',len(out['jobs']))
if __name__=='__main__':main()
