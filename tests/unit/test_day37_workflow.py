from __future__ import annotations

from pathlib import Path
import yaml

ROOT=Path(__file__).resolve().parents[2]
WORKFLOW=ROOT/'.github/workflows/day37-aws-staging.yml'


def test_workflow_dag():
    d=yaml.safe_load(WORKFLOW.read_text())
    jobs=d['jobs']
    assert set(jobs)=={'source','admission','plan','bootstrap','publish','deploy','verify','close','recovery','deploy_plan','gate'}
    for name,job in jobs.items():
        needs=job.get('needs',[])
        for n in [needs] if isinstance(needs,str) else needs:
            assert n in jobs and n!=name
    assert set(jobs['gate']['needs'])==set(jobs)-{'gate'}
    assert jobs['gate']['if']=='${{ always() }}'


def test_aws_oidc_only_on_environment_protected_jobs():
    d=yaml.safe_load(WORKFLOW.read_text())
    for name in ('source','admission','gate'):
        assert 'id-token' not in d['jobs'][name].get('permissions',{})
    for name in ('plan','bootstrap','publish','deploy','verify','close','recovery','deploy_plan'):
        job=d['jobs'][name]
        assert job.get('environment','').startswith('aws-staging-')
        assert job['permissions']['id-token']=='write'
    assert d['permissions']['contents']=='read'
    assert 'id-token' not in d['permissions']


def test_no_unpinned_external_actions_or_merge_keys():
    text=WORKFLOW.read_text()
    assert '<<:' not in text
    d=yaml.safe_load(text)
    for job in d['jobs'].values():
        for step in job['steps']:
            if 'uses' in step and not step['uses'].startswith('./'):
                assert len(step['uses'].split('@',1)[1])==40
    assert "--keyless" not in text or "cosign" in text
    assert "|| :" not in text


def test_exact_source_identity_and_safe_mode_default():
    d=yaml.safe_load(WORKFLOW.read_text())
    inputs=d['on']['workflow_dispatch']['inputs']
    assert inputs['mode']['default']=='audit'
    assert inputs['mode']['options']==['audit','plan','bootstrap','deploy']
    assert d['concurrency']['cancel-in-progress'] is False
    assert 'production' not in str([j.get('environment','') for j in d['jobs'].values()])
