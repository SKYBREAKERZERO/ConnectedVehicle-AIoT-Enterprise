import pytest
from scripts.day37_bootstrap_manual import bootstrap_manual_proof
from scripts.day37_fence import Blocked

@pytest.fixture
def inputs(monkeypatch):
    now={'commit':'a'*40,'run_id':'91','run_attempt':'2',
         'repository':'SKYBREAKERZERO/ConnectedVehicle-AIoT-Enterprise',
         'aws_account_id':'123456789012','region':'ap-northeast-1'}
    for k,v in {'GITHUB_SHA':now['commit'],'GITHUB_RUN_ID':now['run_id'],
                'GITHUB_RUN_ATTEMPT':now['run_attempt'],
                'GITHUB_REPOSITORY':now['repository'],'DAY37_ACCOUNT_ID':now['aws_account_id'],
                'GITHUB_REF':'refs/heads/main','GITHUB_EVENT_NAME':'workflow_dispatch',
                'RECONCILE_PRIOR_COMMIT':'b'*40,'RECONCILE_PRIOR_RUN':'77',
                'RECONCILE_PRIOR_ATTEMPT':'1'}.items():monkeypatch.setenv(k,v)
    old={'schema':2,'state':'ACTIVE','phase':'bootstrap','commit':'b'*40,
         'run_id':'77','run_attempt':'1','plan_sha256':'c'*64,
         'policy_sha256':'d'*64,'aws_account_id':now['aws_account_id'],
         'repository':now['repository'],'image_digest':None}
    plan={'format_version':'1.2','variables':{'enable_service':{'value':False},'desired_count':{'value':0}},
          'resource_changes':[{'change':{'actions':['no-op']},'address':'aws_ecs_cluster.staging'}],
          'output_changes':{}}
    observed={'decision':'STAGING_INFRA_BOOTSTRAPPED','aws_account_id':now['aws_account_id'],
              'commit':now['commit'],'run_id':now['run_id'],'run_attempt':now['run_attempt'],
              'production_authorized':False,'release_authorized':False}
    return old,plan,observed

def test_manual_reconcile_after_external_repair(inputs):
    x=bootstrap_manual_proof(*inputs,0)
    assert x['decision']=='MANUAL_BOOTSTRAP_AWS_AND_TERRAFORM_RECONCILED'
    assert x['prior_plan_sha256']=='c'*64 and x['restored_registry_digest'] is None

@pytest.mark.parametrize('field',('phase','old_run','drift','enabled','wrong_account','no_aws','nonzero'))
def test_manual_bootstrap_negative(inputs,field):
    f,p,o=inputs
    if field=='phase': f['phase']='deploy'
    if field=='old_run':f['run_id']='76'
    if field=='drift':p['resource_changes'][0]['change']['actions']=['update']
    if field=='enabled':p['variables']['enable_service']['value']=True
    if field=='wrong_account':o['aws_account_id']='999999999999'
    if field=='no_aws':o['decision']='BLOCKED'
    with pytest.raises(Blocked):bootstrap_manual_proof(f,p,o,2 if field=='nonzero' else 0)
