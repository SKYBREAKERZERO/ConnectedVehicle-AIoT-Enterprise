from pathlib import Path
import yaml

def test_enterprise_workflow_includes_critical_proof_checks():
    path=Path('.github/workflows/day37-aws-staging.yml')
    assert path.is_file(),'Day37 enterprise workflow must be installed'
    doc=yaml.safe_load(path.read_text())
    assert 'bootstrap_close' in doc['jobs']
    actual='\n'.join(s.get('run','') for j in doc['jobs'].values() for s in j.get('steps',[]))
    for key in ('day37_fence mark --phase bootstrap','day37_fence mark --phase deploy',
                'day37_reconcile --phase bootstrap','day37_reconcile --phase deploy',
                'day37_fence recovery-check','day37_fence close', 'day37_enterprise_gate'):
        assert key in actual,key
    assert 'day37_plan_transport mark-fence' not in actual
    assert 'day37_plan_transport close-fence' not in actual
