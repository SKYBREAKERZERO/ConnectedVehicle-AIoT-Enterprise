"""Generate independent manual Bootstrap reconciliation workflow; no Apply."""
from pathlib import Path
import yaml
root=Path(__file__).resolve().parents[1]
base=yaml.safe_load((root/'.github/workflows/day37-aws-staging.yml').read_text())
close_env=base['jobs']['bootstrap_close']['env'].copy()
close_env.update({
 'RECONCILE_COMMIT':'${{ inputs.release_commit }}',
 'RECONCILE_PRIOR_COMMIT':'${{ inputs.prior_commit }}',
 'RECONCILE_PRIOR_RUN':'${{ inputs.prior_run_id }}',
 'RECONCILE_PRIOR_ATTEMPT':'${{ inputs.prior_attempt }}',
})
inputs={k:{'description':text,'required':True,'type':'string'} for k,text in {
    'release_commit':'Current protected main HEAD SHA',
    'prior_commit':'Commit of failed Bootstrap fence',
    'prior_run_id':'GitHub Run ID of failed Bootstrap fence',
    'prior_attempt':'GitHub Run Attempt of failed Bootstrap fence',
}.items()}
run_identity="""set -euo pipefail
[[ "$GITHUB_REF" == 'refs/heads/main' && "$GITHUB_EVENT_NAME" == 'workflow_dispatch' ]]
[[ "$GITHUB_SHA" == "$RECONCILE_COMMIT" && "$RECONCILE_COMMIT" =~ ^[0-9a-f]{40}$ ]]
[[ "$RECONCILE_PRIOR_COMMIT" =~ ^[0-9a-f]{40}$ && "$RECONCILE_PRIOR_RUN" =~ ^[1-9][0-9]*$ && "$RECONCILE_PRIOR_ATTEMPT" =~ ^[1-9][0-9]*$ ]]
HEAD=$(gh api repos/SKYBREAKERZERO/ConnectedVehicle-AIoT-Enterprise/branches/main --jq .commit.sha)
[[ "$HEAD" == "$GITHUB_SHA" ]] || { echo 'BLOCKED: protected main changed' >&2; exit 1; }
python -m scripts.day37_preflight config --mode recovery
"""
run_reconcile="""set -euo pipefail
umask 077
mkdir -p .day37/bootstrap-manual
python -m scripts.day37_fence read-fence --output .day37/bootstrap-manual/fence.json
python - <<'PYCODE'
import os
from scripts.day37_fence import load, require
record = load('.day37/bootstrap-manual/fence.json')
require(record.get('phase') == 'bootstrap','only Bootstrap fence may be reconciled here')
for key, label in [('commit','RECONCILE_PRIOR_COMMIT'),('run_id','RECONCILE_PRIOR_RUN'),('run_attempt','RECONCILE_PRIOR_ATTEMPT')]:
    require(str(record.get(key)) == os.environ[label], 'previous run differs from ACTIVE fence')
PYCODE
bash scripts/day37_tf.sh init
export TF_VAR_enable_service=false TF_VAR_desired_count=0
set +e
terraform -chdir="${DAY37_TF_ROOT}" plan -detailed-exitcode -input=false -lock-timeout=30s -no-color -out="${PWD}/.day37/bootstrap-manual/no-drift.tfplan" > .day37/bootstrap-manual/terraform-private.log 2>&1
RC=$?
set -e
[[ "$RC" -eq 0 ]] || { echo 'BLOCKED: partial Bootstrap Apply still unreconciled' >&2; exit 1; }
terraform -chdir="${DAY37_TF_ROOT}" show -json "${PWD}/.day37/bootstrap-manual/no-drift.tfplan" > .day37/bootstrap-manual/no-drift.json
python -m scripts.day37_bootstrap_manual --fence .day37/bootstrap-manual/fence.json --terraform-json .day37/bootstrap-manual/no-drift.json --terraform-exit-code "$RC" --output .day37/bootstrap-manual/manual-proof.json
python -m scripts.day37_fence manual-close --phase bootstrap --fence .day37/bootstrap-manual/fence.json --proof .day37/bootstrap-manual/manual-proof.json --output .day37/bootstrap-manual/closed-fence.json
"""
yml={
 'name':'Day37 manual Bootstrap reconciliation (no automatic repair)',
 'on':{'workflow_dispatch':{'inputs':inputs}},
 'permissions':{'contents':'read'},
 'concurrency':{'group':'day37-aws-staging-exclusive','cancel-in-progress':False},
 'defaults':{'run':{'shell':'bash'}},
 'jobs':{'bootstrap_reconcile':{
    'name':'Independently reconcile previous Bootstrap after approved repair',
    'runs-on':'ubuntu-24.04','timeout-minutes':45,'environment':'aws-staging-recovery',
    'permissions':{'contents':'read','id-token':'write'},'env':close_env,
    'steps':[
      {'uses':'actions/checkout@11d5960a326750d5838078e36cf38b85af677262','with':{'persist-credentials':False,'fetch-depth':0}},
      {'uses':'./.github/actions/setup-ci-runtime'},
      {'uses':'hashicorp/setup-terraform@b9cd54a3c349d3f38e8881555d616ced269862dd','with':{'terraform_version':'1.14.7','terraform_wrapper':False}},
      {'name':'Verify protected main and previous run identity','env':{'GH_TOKEN':'${{ github.token }}'},'run':run_identity},
      {'uses':'aws-actions/configure-aws-credentials@e1253824e5c10ff9df46874f81ed3ec929e19cfd','with':{'aws-region':'ap-northeast-1','role-to-assume':'${{ env.DAY37_ROLE_ARN }}','role-session-name':'day37-bootstrap-manual-${{ github.run_id }}-${{ github.run_attempt }}','role-duration-seconds':1800}},
      {'name':'Verify AWS recovery Role','run':'python -m scripts.day37_preflight live --mode recovery'},
      {'name':'Read ACTIVE fence, prove zero drift, live AWS, CAS close','run':run_reconcile},
      {'if':'${{ always() }}','uses':'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02','with':{'name':'day37-bootstrap-manual-${{ github.run_id }}-${{ github.run_attempt }}','path':'.day37/bootstrap-manual/fence.json\n.day37/bootstrap-manual/manual-proof.json\n.day37/bootstrap-manual/closed-fence.json','include-hidden-files':True,'if-no-files-found':'warn','retention-days':30}},
    ]
 }}
}
p=root/'.github/workflows/day37-bootstrap-reconcile.yml'
p.write_text(yaml.safe_dump(yml,allow_unicode=True,sort_keys=False,width=140))
print('WROTE',p)
