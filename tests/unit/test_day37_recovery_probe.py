import json
import sys
from pathlib import Path
import pytest
from scripts import day37_fence as f
from scripts.day37_fence import Blocked

@pytest.fixture
def env(monkeypatch):
    values={'GITHUB_SHA':'a'*40,'GITHUB_RUN_ID':'17','GITHUB_RUN_ATTEMPT':'1',
            'GITHUB_REPOSITORY':'SKYBREAKERZERO/ConnectedVehicle-AIoT-Enterprise',
            'DAY37_ACCOUNT_ID':'123456789012', 'GITHUB_REF':'refs/heads/main',
            'GITHUB_EVENT_NAME':'workflow_dispatch'}
    for key,value in values.items():monkeypatch.setenv(key,value)
    return f.current_identity()

@pytest.mark.parametrize('phase,expected', [('deploy',0),('bootstrap',1)])
def test_recovery_probe_uses_live_s3_and_refuses_foreign_phase(tmp_path,monkeypatch,env,phase,expected):
    record={**env,'schema':2,'state':'ACTIVE','phase':phase,'plan_sha256':'f'*64}
    class LiveS3:
        def read(self):return record,'etag1'
    monkeypatch.setattr(f,'s3',lambda:LiveS3())
    output=tmp_path/'fence.json';status=tmp_path/'status.json'
    monkeypatch.setattr(sys,'argv',['day37_fence','probe','--fence-output',str(output),'--status-output',str(status)])
    assert f.main()==expected
    if expected==0:
        assert json.loads(output.read_text())==record
        assert json.loads(status.read_text())['active']=='true'
    else:assert not output.exists()

def test_recovery_probe_no_active_fence(tmp_path,monkeypatch,env):
    class LiveS3:
        def read(self):return None,None
    monkeypatch.setattr(f,'s3',lambda:LiveS3())
    out=tmp_path/'fence.json';status=tmp_path/'status.json'
    monkeypatch.setattr(sys,'argv',['day37_fence','probe','--fence-output',str(out),'--status-output',str(status)])
    assert f.main()==0
    assert json.loads(status.read_text())['active']=='false'
    assert not out.exists()
