"""Final release acceptance requires actual per-Task and zero-drift closure evidence."""
from __future__ import annotations
import json
from pathlib import Path
import pytest
from scripts import day37_gate as g

SHA='a'*40
DIGEST='sha256:'+'b'*64
URI='123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/cv-ota-staging/vehicle-api@'+DIGEST

def make(tmp):
    needs={name:{'result':'success' if name in {'source','admission','publish','deploy_plan','deploy','verify','close'} else 'skipped'}
           for name in ('source','admission','plan','bootstrap','publish','deploy_plan','deploy','verify','close','recovery')}
    identity={'commit':SHA,'run_id':'123','run_attempt':'1'}
    files={
      'admission/admission.json':{**identity,'release_authorized':False,'day36_run_id':'36','day36_attempt':'2'},
      'deploy-plan/plan-summary.json':{'phase':'deploy','decision':'NON_DESTRUCTIVE_TERRAFORM_PLAN'},
      'deploy-plan/receipt.json':{**identity,'phase':'deploy','decision':'PRIVATE_VERSIONED_PLAN_STORED','image_digest':DIGEST},
      'publish/release.json':{**identity,'registry_digest':DIGEST,'image_uri':URI,'day36_run_id':'36','day36_attempt':'2'},
      'deploy/deployment.json':{**identity,'registry_digest':DIGEST,'image_uri':URI},
      'verify/verified.json':{**identity,'decision':'ECS_TASK_DIGEST_HEALTH_VERIFIED','image_uri':URI,'registry_digest':DIGEST,
          'desired_count':2,'tasks':[{'image_digest':DIGEST,'task_arn':'a'}, {'image_digest':DIGEST,'task_arn':'b'}],
          'aws_account_id':'123456789012'},
      'close/closed.json':{**identity,'registry_digest':DIGEST,'decision':'STAGING_TERRAFORM_ZERO_DRIFT_AND_FENCE_CLOSED'},
    }
    for file,body in files.items():
        p=tmp/file;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(body))
    return needs,files

def test_closure_gate_passes_only_fully_bound_immutable_image(tmp_path):
    needs,_=make(tmp_path)
    assert g.final('deploy',needs,tmp_path,SHA,'123','1')['decision']=='AWS_STAGING_SERVICE_VERIFIED'

def test_missing_closure_blocks(tmp_path):
    needs,_=make(tmp_path)
    (tmp_path/'close/closed.json').unlink()
    with pytest.raises(ValueError):g.final('deploy',needs,tmp_path,SHA,'123','1')

def test_foreign_task_digest_blocks(tmp_path):
    needs,files=make(tmp_path)
    p=tmp_path/'verify/verified.json';d=json.loads(p.read_text());d['tasks'][1]['image_digest']='sha256:'+'c'*64;p.write_text(json.dumps(d))
    with pytest.raises(ValueError,match='health proof'):
        g.final('deploy',needs,tmp_path,SHA,'123','1')

def test_recovery_result_does_not_unblock_failed_release(tmp_path):
    needs,_=make(tmp_path)
    needs['deploy']['result']='failure'
    needs['verify']['result']='skipped'
    needs['close']['result']='skipped'
    needs['recovery']['result']='success'
    with pytest.raises(ValueError,match='job status'):
        g.final('deploy',needs,tmp_path,SHA,'123','1')
