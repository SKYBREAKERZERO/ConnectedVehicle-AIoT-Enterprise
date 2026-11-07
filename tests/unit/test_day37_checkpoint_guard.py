import pytest
from scripts.day37_checkpoint_guard import equal_original
from scripts.day37_fence import Blocked

def sample():
    return {'commit':'a'*40,'run_id':'1','run_attempt':'1',
            'aws_account_id':'123456789012','cluster':'cv-ota-staging',
            'service':'cv-ota-staging-api','exists':True,
            'previous_task_definition':'arn:aws:ecs:ap-northeast-1:123456789012:task-definition/cv-ota-staging-api:1',
            'previous_desired_count':2, 'production_authorized':False,'release_authorized':False}

def test_no_checkpoints_changed():
    x=sample();equal_original(x,x.copy())

@pytest.mark.parametrize('field',('commit','run_attempt','service','exists','previous_task_definition','previous_desired_count'))
def test_changed_baseline_blocks_before_apply(field):
    original=sample();fresh=sample();fresh[field]='modified'
    with pytest.raises(Blocked):equal_original(original,fresh)

def test_non_staging_checkpoint_refused():
    original=sample();original['production_authorized']=True
    with pytest.raises(Blocked):equal_original(original,sample())
