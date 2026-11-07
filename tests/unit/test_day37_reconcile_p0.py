import pytest
from scripts.day37_fence import Blocked
from scripts.day37_reconcile import zero_drift, proof

GOOD={'format_version':'1.2','resource_changes':[{'address':'a','change':{'actions':['no-op']}}],
      'output_changes':{'x':{'actions':['no-op']}}}

def test_no_drift_accepts_only_noop():
    zero_drift(GOOD)

@pytest.mark.parametrize('change',[
  {'resource_changes':[{'address':'r','change':{'actions':['update']}}]},
  {'resource_drift':[{'address':'r','change':{'actions':['update']}}]},
  {'output_changes':{'x':{'actions':['update']}}},
  {'errored':True},
  {'format_version':None}
])
def test_no_drift_blocks_unexpected_changes(change):
    with pytest.raises(Blocked): zero_drift({**GOOD,**change})


def test_bootstrap_proof_negative(monkeypatch):
    # Same actual identity shape as the real transport-bound v2 fence.
    from scripts.day37_fence import REPO
    env={'GITHUB_SHA':'a'*40,'GITHUB_RUN_ID':'1','GITHUB_RUN_ATTEMPT':'1',
         'GITHUB_REPOSITORY':REPO,'DAY37_ACCOUNT_ID':'123456789012',
         'GITHUB_REF':'refs/heads/main','GITHUB_EVENT_NAME':'workflow_dispatch'}
    for k,v in env.items(): monkeypatch.setenv(k,v)
    fence={'schema':2,'state':'ACTIVE','phase':'bootstrap','repository':REPO,
           'commit':'a'*40,'run_id':'1','run_attempt':'1',
           'region':'ap-northeast-1','aws_account_id':'123456789012',
           'plan_sha256':'b'*64,'policy_sha256':'c'*64}
    live={'commit':'a'*40,'run_id':'1','run_attempt':'1','aws_account_id':'123456789012',
          'decision':'STAGING_INFRA_BOOTSTRAPPED','production_authorized':False,'release_authorized':False}
    assert proof(fence,GOOD,live,terraform_exit_code=0)['decision']=='AWS_AND_TERRAFORM_RECONCILED'
    with pytest.raises(Blocked):proof(fence,GOOD,live,terraform_exit_code=2)
    with pytest.raises(Blocked):proof(fence,GOOD,{**live,'decision':'APPROVED'},terraform_exit_code=0)
