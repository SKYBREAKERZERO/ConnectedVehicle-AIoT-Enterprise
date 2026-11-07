import pytest
from scripts.day37_recovery_guard import examine
from scripts.day37_fence import Blocked

@pytest.fixture
def records(monkeypatch):
    fields={'GITHUB_SHA':'a'*40,'GITHUB_RUN_ID':'17','GITHUB_RUN_ATTEMPT':'2',
            'GITHUB_REPOSITORY':'SKYBREAKERZERO/ConnectedVehicle-AIoT-Enterprise',
            'DAY37_ACCOUNT_ID':'123456789012','GITHUB_REF':'refs/heads/main',
            'GITHUB_EVENT_NAME':'workflow_dispatch',
            'DAY37_CLUSTER':'cv-ota-staging','DAY37_SERVICE':'cv-ota-staging-api',
            'DAY37_ECR_REPOSITORY':'cv-ota-staging/api'}
    for k,v in fields.items():monkeypatch.setenv(k,v)
    old='arn:aws:ecs:ap-northeast-1:123456789012:task-definition/cv-ota-staging-api:1'
    new='arn:aws:ecs:ap-northeast-1:123456789012:task-definition/cv-ota-staging-api:2'
    digest='sha256:'+'f'*64
    fence={'state':'ACTIVE','phase':'deploy','commit':'a'*40,'run_id':'17',
           'run_attempt':'2','aws_account_id':'123456789012','image_digest':digest}
    checkpoint={'commit':'a'*40,'run_id':'17','run_attempt':'2','aws_account_id':'123456789012',
                'cluster':'cv-ota-staging','service':'cv-ota-staging-api','exists':True,
                'previous_task_definition':old,'previous_desired_count':2}
    svc={'status':'ACTIVE','serviceName':'cv-ota-staging-api','taskDefinition':new,'desiredCount':2}
    td={'taskDefinitionArn':new,'containerDefinitions':[{'name':'vehicle-api',
        'image':'123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/cv-ota-staging/api@'+digest}]}
    return fence,checkpoint,svc,td

def test_known_failed_digest_allows_bounded_restore(records):
    f,c,s,t=records
    result=examine(f,c,s,t)
    assert result['decision']=='EXACT_FAILED_RELEASE_RESTORE_ALLOWED' and result['restore_required'] is True

def test_current_already_old_is_not_mutated(records):
    f,c,s,t=records;s['taskDefinition']=c['previous_task_definition']
    result=examine(f,c,s,None)
    assert result['restore_required'] is False

@pytest.mark.parametrize('scenario',('foreign_image','foreign_account','future_revision','bad_count','missing_old','invalid_cluster','untrusted_status'))
def test_unknown_generation_blocks(records,scenario):
    f,c,s,t=records
    if scenario=='foreign_image':t['containerDefinitions'][0]['image']='untrusted'
    if scenario=='foreign_account':f['aws_account_id']='999999999999'
    if scenario=='future_revision':s['taskDefinition']=s['taskDefinition'].replace(':2',':3')
    if scenario=='bad_count':c['previous_desired_count']=0
    if scenario=='missing_old':c['exists']=False
    if scenario=='invalid_cluster':c['cluster']='prod-cluster'
    if scenario=='untrusted_status':s['status']='DRAINING'
    with pytest.raises(Blocked):examine(f,c,s,t)
