import json
import hashlib
from pathlib import Path
from scripts.day37_fence import canonical
import pytest
from scripts.day37_fence import Blocked
from scripts.day37_release_guard import final_check, ALL_JOBS, JOB_SETS, EXPECTED_DECISIONS

@pytest.mark.parametrize('mode',tuple(EXPECTED_DECISIONS))
def test_final_correct_modes_and_denied_production(tmp_path,monkeypatch,mode):
    for k,v in {'GITHUB_SHA':'a'*40,'GITHUB_RUN_ID':'17','GITHUB_RUN_ATTEMPT':'1'}.items():
        monkeypatch.setenv(k,v)
    needs={job:{'result':'success' if job in JOB_SETS[mode] else 'skipped'} for job in ALL_JOBS}
    monkeypatch.setenv('PIPELINE_NEEDS',json.dumps(needs))
    final=tmp_path/'final.json'
    final.write_text(json.dumps({'decision': EXPECTED_DECISIONS[mode], 'commit':'a'*40,
        'run_id':'17','run_attempt':'1','production_authorized':False,'release_authorized':False}))
    folder=tmp_path/'evidence'
    expected={'audit':[], 'plan':['admission/admission.json','plan/plan-summary.json'],
              'bootstrap':['admission/admission.json','plan/receipt.json','bootstrap/bootstrap.json'],
              'deploy':['admission/admission.json','publish/release.json','deploy-plan/receipt.json',
                        'deploy/deployment.json','verify/verified.json','close/closed.json']}[mode]
    for relative in expected:
        p=folder/relative
        p.parent.mkdir(parents=True,exist_ok=True)
        p.write_text('{}')
    if mode in ('bootstrap', 'deploy'):
        phase='bootstrap' if mode=='bootstrap' else 'deploy'
        where='bootstrap' if mode=='bootstrap' else 'close'
        identity={'schema':2,'phase':phase,'commit':'a'*40,'run_id':'17','run_attempt':'1',
                  'plan_sha256':'b'*64,'policy_sha256':'c'*64}
        rec={**identity,'state':'CLOSED'}
        prf={**identity,'decision':'AWS_AND_TERRAFORM_RECONCILED','terraform_exit_code':0,
             'live_aws_verified':True}
        rec['proof_sha256']=hashlib.sha256(canonical(prf)).hexdigest()
        source='plan/receipt.json' if mode=='bootstrap' else 'deploy-plan/receipt.json'
        (folder/source).write_text(json.dumps({'plan_sha256':'b'*64,'policy_sha256':'c'*64}))
        proofpath=folder/where/'proof.json'
        proofpath.write_text(json.dumps(prf))
        closed=folder/where/('closed-fence.json' if mode=='bootstrap' else 'fence-closed.json')
        closed.write_text(json.dumps(rec))
    final_check(mode,str(folder),str(final))
    monkeypatch.setenv('PIPELINE_NEEDS',json.dumps({**needs,'recovery':{'result':'success'}}))
    with pytest.raises(Blocked):final_check(mode,str(folder),str(final))
    monkeypatch.setenv('PIPELINE_NEEDS',json.dumps(needs))
    final.write_text(json.dumps({'decision':'READY','commit':'a'*40,
        'run_id':'17','run_attempt':'1','production_authorized':False,'release_authorized':False}))
    with pytest.raises(Blocked):final_check(mode,str(folder),str(final))
