"""Update existing Day37 tests for the added independent Bootstrap closure.

These remain strict safety assertions (not test skipping or lowering coverage).
Refuse unknown upstream files instead of applying unsafe fuzzy replacements.
"""
from __future__ import annotations

def exact(s: str, old: str, new: str, label: str) -> str:
    if s.count(old)!=1:
        raise ValueError(f'BLOCKED: test contract anchor changed {label}: {s.count(old)}')
    return s.replace(old,new,1)

def workflow_test(text: str) -> str:
    old='        "bootstrap",\n        "publish",'
    new='        "bootstrap",\n        "bootstrap_close",\n        "publish",'
    if text.count(old)!=2:
        raise ValueError('BLOCKED: Day37 original DAG/OIDC expected two anchors')
    text=text.replace(old,new,2)
    text += '''\n\ndef test_bootstrap_closure_uses_independent_recovery_role():\n    jobs = yaml.safe_load(WORKFLOW.read_text())["jobs"]\n    assert jobs["bootstrap_close"]["environment"] == "aws-staging-recovery"\n    assert "bootstrap" in jobs["bootstrap_close"]["needs"]\n    assert "bootstrap_close" in jobs["gate"]["needs"]\n'''
    return text


def p1_test(text: str) -> str:
    text=exact(text,'    assert "mark-fence" in text and text.index("mark-fence") < text.index(" apply ")',
       '''    assert "day37_fence mark --phase deploy" in text\n    assert text.index("day37_fence mark --phase deploy") < text.index('terraform -chdir="${DAY37_TF_ROOT}" apply')''','P1 mark fence')
    text=exact(text,'    assert "-detailed-exitcode" in text and "close-fence" in text\n    assert "close-fence" not in "\\n".join(x.get("run", "") for x in jobs["recovery"]["steps"])',
        '''    assert "-detailed-exitcode" in text and "day37_fence close" in text\n    assert "day37_fence close" not in "\\n".join(x.get("run", "") for x in jobs["recovery"]["steps"])''','P1 closure proof')
    return text

def manual_test(text: str) -> str:
    old='body.index("close-fence")'
    if text.count(old)!=2:
        raise ValueError('BLOCKED: original manual reconcile order assertions changed')
    return text.replace(old,'body.index("day37_fence manual-close")',2)


FILES={
 'tests/unit/test_day37_workflow.py':workflow_test,
 'tests/unit/test_day37_p1_workflow.py':p1_test,
 'tests/unit/test_day37_manual_reconcile.py':manual_test,
}
