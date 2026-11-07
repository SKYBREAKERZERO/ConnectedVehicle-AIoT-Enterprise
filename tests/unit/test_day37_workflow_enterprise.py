from pathlib import Path
import subprocess
import yaml
import pytest

ROOT=Path(__file__).resolve().parents[2]

def test_enterprise_workflow_roles_and_fence():
    w=yaml.safe_load((ROOT/'.github/workflows/day37-aws-staging.yml').read_text())
    jobs=w['jobs']
    assert len(jobs)==12
    assert jobs['bootstrap_close']['environment']=='aws-staging-recovery'
    assert jobs['bootstrap_close']['env']['DAY37_ROLE_ARN']=='${{ vars.DAY37_RECOVERY_ROLE_ARN }}'
    assert 'bootstrap_close' in jobs['gate']['needs']
    for job in ('bootstrap','deploy'):
        run='\n'.join(s.get('run','') for s in jobs[job]['steps'])
        assert 'day37_fence mark' in run
        assert run.index('day37_fence mark')<run.index('terraform -chdir="${DAY37_TF_ROOT}" apply')
        assert 'day37_plan_transport mark-fence' not in run
    bootstrap_run='\n'.join(s.get('run','') for s in jobs['bootstrap']['steps'])
    assert 'day37_fence close' not in bootstrap_run
    bclose='\n'.join(s.get('run','') for s in jobs['bootstrap_close']['steps'])
    assert 'day37_reconcile --phase bootstrap' in bclose and 'day37_fence close' in bclose
    assert 'day37_enterprise_gate' in '\n'.join(s.get('run','') for s in jobs['gate']['steps'])

@pytest.mark.parametrize('name',('day37-aws-staging.yml','day37-bootstrap-reconcile.yml'))
def test_all_inline_bash_syntax(name):
    w=yaml.safe_load((ROOT/'.github/workflows'/name).read_text())
    assert 'workflow_dispatch' in w['on']
    for job in w['jobs'].values():
        for s in job['steps']:
            assert 'uses' in s or 'run' in s
            if 'run' in s:
                result=subprocess.run(['bash','-n'],input=s['run'],capture_output=True,text=True)
                assert result.returncode==0,(name,s.get('name'),result.stderr)

def test_production_authority_not_in_bootstrap_recovery():
    for name in ('day37-aws-staging.yml','day37-bootstrap-reconcile.yml'):
        raw=(ROOT/'.github/workflows'/name).read_text()
        assert 'aws-production' not in raw
        assert 'terraform destroy' not in raw
        assert 'day37_fence manual-close --phase bootstrap' in raw if 'bootstrap-reconcile' in name else True
