import pytest
from scripts.day37_fence import Blocked,REPO
from scripts.day37_manual_proof import build

@pytest.fixture
def context(monkeypatch):
    for k,v in {'GITHUB_SHA':'a'*40,'GITHUB_RUN_ID':'22','GITHUB_RUN_ATTEMPT':'1',
      'GITHUB_REPOSITORY':REPO,'DAY37_ACCOUNT_ID':'123456789012',
      'GITHUB_REF':'refs/heads/main','GITHUB_EVENT_NAME':'workflow_dispatch',
      'RECONCILE_PRIOR_COMMIT':'b'*40,'RECONCILE_PRIOR_RUN':'21',
      'RECONCILE_PRIOR_ATTEMPT':'1'}.items(): monkeypatch.setenv(k,v)
    fence={'schema':2,'state':'ACTIVE','phase':'deploy','commit':'b'*40,'run_id':'21',
           'run_attempt':'1','repository':REPO,'aws_account_id':'123456789012',
           'plan_sha256':'c'*64}
    plan={'format_version':'1.2','resource_changes':[]}
    live={'decision':'ECS_TASK_DIGEST_HEALTH_VERIFIED','registry_digest':'sha256:'+'d'*64,
          'desired_count':2,'running_count':2,'tasks':[{},{}],
          'commit':'a'*40,'run_id':'22','run_attempt':'1','aws_account_id':'123456789012',
          'production_authorized':False,'release_authorized':False}
    return fence,plan,live

def test_manual_reconcile_requires_exact_restored_image_and_noop(context):
    fence,plan,live=context
    out=build(fence,plan,live,0,'sha256:'+'d'*64)
    assert out['prior_plan_sha256']=='c'*64
    with pytest.raises(Blocked): build(fence,plan,live,2,'sha256:'+'d'*64)
    with pytest.raises(Blocked): build(fence,plan,{**live,'registry_digest':'sha256:'+'e'*64},0,'sha256:'+'d'*64)
    with pytest.raises(Blocked): build({**fence,'run_id':'20'},plan,live,0,'sha256:'+'d'*64)
