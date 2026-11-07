import json
import pytest
from scripts.day37_enterprise_gate import verify_dag
from scripts.day37_release_guard import ALL_JOBS,JOB_SETS
from scripts.day37_fence import Blocked

@pytest.mark.parametrize('mode',('audit','plan','bootstrap','deploy'))
def test_entire_enterprise_dag(mode):
    needs={k:{'result':'success' if k in JOB_SETS[mode] else 'skipped'} for k in ALL_JOBS}
    verify_dag(mode,needs)
    needs['bootstrap_close']['result']='success' if mode!='bootstrap' else 'skipped'
    with pytest.raises(Blocked):verify_dag(mode,needs)

def test_missing_or_cancelled_job_blocks():
    needs={k:{'result':'skipped'} for k in ALL_JOBS}
    needs['source']['result']='success'
    needs['bootstrap_close']['result']='cancelled'
    with pytest.raises(Blocked):verify_dag('audit',needs)
    needs.pop('bootstrap_close')
    with pytest.raises(Blocked):verify_dag('audit',needs)
