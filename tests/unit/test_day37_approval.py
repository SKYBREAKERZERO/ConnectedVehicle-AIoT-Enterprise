from datetime import datetime, timezone, timedelta
import json
import pytest
from scripts.day37_fence import Blocked
from scripts.day37_approval import claim,verify,final_verify

@pytest.fixture
def context(monkeypatch):
    fields={'GITHUB_SHA':'a'*40,'GITHUB_RUN_ID':'123','GITHUB_RUN_ATTEMPT':'1',
            'GITHUB_REPOSITORY':'SKYBREAKERZERO/ConnectedVehicle-AIoT-Enterprise',
            'GITHUB_REF':'refs/heads/main','GITHUB_EVENT_NAME':'workflow_dispatch',
            'DAY37_ACCOUNT_ID':'123456789012'}
    for k,v in fields.items():monkeypatch.setenv(k,v)
    dt=datetime.now(timezone.utc)-timedelta(minutes=2)
    rec={'decision':'PRIVATE_VERSIONED_PLAN_STORED','phase':'bootstrap','commit':'a'*40,
         'run_id':'123','run_attempt':'1','aws_account_id':'123456789012',
         'plan_sha256':'b'*64,'policy_sha256':'c'*64,'created_at':dt.isoformat()}
    return rec,dt

def approval(rec,dt,**changes):
    c=claim('bootstrap',rec)
    row={'state':'approved','comment':json.dumps(c),'user':{'login':'different-reviewer','id':41},
         'environments':[{'name':'aws-staging-bootstrap'}],
         'created_at':(dt+timedelta(minutes=1)).isoformat()}
    row.update(changes)
    return row

def test_approval_binding_correct(context):
    rec,dt=context
    result=verify('bootstrap',rec,[approval(rec,dt)],actor='requester')
    assert result['decision']=='EXACT_GITHUB_ENVIRONMENT_PLAN_APPROVED'
    final_verify(result,'bootstrap',rec,[approval(rec,dt)],actor='requester')

@pytest.mark.parametrize('scenario',('wrong_plan','wrong_policy','self','rejected','stale','prior','wrong_environment','duplicate'))
def test_approval_fails_closed(context,scenario):
    rec,dt=context
    row=approval(rec,dt)
    if scenario=='wrong_plan':
        value=json.loads(row['comment']);value['plan_sha256']='e'*64;row['comment']=json.dumps(value)
    if scenario=='wrong_policy':
        value=json.loads(row['comment']);value['policy_sha256']='e'*64;row['comment']=json.dumps(value)
    if scenario=='self': row['user']['login']='requester'
    if scenario=='rejected': row['state']='rejected'
    if scenario=='stale':row['created_at']=(dt+timedelta(hours=6)).isoformat()
    if scenario=='prior':row['created_at']=(dt-timedelta(seconds=1)).isoformat()
    if scenario=='wrong_environment':row['environments']=[{'name':'aws-staging-plan'}]
    if scenario=='duplicate': row['comment']=row['comment'][:-1]+', "commit":"'+('a'*40)+'"}'
    with pytest.raises((Blocked,ValueError)):
        verify('bootstrap',rec,[row],actor='requester')

def test_forged_artifact_refused(context):
    rec,dt=context
    a=verify('bootstrap',rec,[approval(rec,dt)],actor='requester')
    with pytest.raises(Blocked):final_verify({**a,'reviewer':'other'},'bootstrap',rec,[approval(rec,dt)],actor='requester')
