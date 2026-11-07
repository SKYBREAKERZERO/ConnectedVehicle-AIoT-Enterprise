import sys
from pathlib import Path
import json
import pytest
from scripts import day37_fence as f

@pytest.fixture
def context(tmp_path,monkeypatch):
    env={'GITHUB_SHA':'a'*40,'GITHUB_RUN_ID':'8','GITHUB_RUN_ATTEMPT':'1',
         'GITHUB_REPOSITORY':'SKYBREAKERZERO/ConnectedVehicle-AIoT-Enterprise',
         'DAY37_ACCOUNT_ID':'123456789012','GITHUB_REF':'refs/heads/main',
         'GITHUB_EVENT_NAME':'workflow_dispatch'}
    for k,v in env.items():monkeypatch.setenv(k,v)
    record={**f.current_identity(),'schema':2,'state':'ACTIVE','phase':'bootstrap',
            'plan_sha256':'b'*64,'policy_sha256':'c'*64,'image_digest':None}
    proof={'decision':'MANUAL_BOOTSTRAP_AWS_AND_TERRAFORM_RECONCILED','phase':'bootstrap',
           'terraform_exit_code':0,'live_aws_verified':True,
           'production_authorized':False,'release_authorized':False,
           'prior_commit':record['commit'],'prior_run_id':record['run_id'],
           'prior_run_attempt':record['run_attempt'],
           'prior_plan_sha256':record['plan_sha256'],'prior_policy_sha256':record['policy_sha256'],
           'aws_account_id':record['aws_account_id'],'repository':record['repository'],
           'reconciler_commit':record['commit'],'reconciler_run_id':record['run_id'],
           'reconciler_run_attempt':record['run_attempt'],'restored_registry_digest':None}
    monkeypatch.setattr(f,'require_closure_role',lambda phase:None)
    class Memory:
        def __init__(self):self.data=record;self.write_count=0
        def read(self):return self.data,'etag1'
        def cas(self,record,etag):self.data=record;self.write_count+=1
    memory=Memory()
    monkeypatch.setattr(f,'s3',lambda:memory)
    file=tmp_path/'fence.json';file.write_text(json.dumps(record))
    pr=tmp_path/'proof.json';pr.write_text(json.dumps(proof))
    return file,pr,memory

def test_manual_deploy_cannot_close_bootstrap_fence(context,tmp_path,monkeypatch):
    record,proof,memory=context
    monkeypatch.setattr(sys,'argv',['day37_fence','manual-close','--phase','deploy',
        '--fence',str(record),'--proof',str(proof),'--output',str(tmp_path/'closed.json')])
    assert f.main()==1
    assert memory.write_count==0 and memory.data['state']=='ACTIVE'

def test_bootstrap_can_close_only_with_correct_policy_proof(context,tmp_path,monkeypatch):
    record,proof,memory=context
    monkeypatch.setattr(sys,'argv',['day37_fence','manual-close','--phase','bootstrap',
        '--fence',str(record),'--proof',str(proof),'--output',str(tmp_path/'closed.json')])
    assert f.main()==0
    assert memory.write_count==1 and memory.data['state']=='CLOSED'
