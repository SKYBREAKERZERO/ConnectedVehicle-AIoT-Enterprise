"""Validate GitHub Actions needs context; YAML parsing alone misses invalid DAG refs."""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
FILES = (
    ROOT / '.github/workflows/day37-aws-staging.yml',
    ROOT / '.github/workflows/day37-bootstrap-reconcile.yml',
    ROOT / '.github/workflows/day37-reconcile.yml',
)


def test_workflow_needs_references_are_direct_dependencies() -> None:
    for path in FILES:
        doc = yaml.safe_load(path.read_text(encoding='utf-8'))
        jobs = doc['jobs']
        for name, job in jobs.items():
            dependencies = job.get('needs', [])
            dependencies = [dependencies] if isinstance(dependencies, str) else dependencies
            for dep in dependencies:
                assert dep in jobs and dep != name, (path.name, name, dep)
            for referenced in re.findall(r'needs\.([A-Za-z0-9_-]+)', json.dumps(job)):
                assert referenced in dependencies, (path.name, name, referenced)


def test_manual_reconcile_workflows_are_dispatch_only() -> None:
    for path in FILES[1:]:
        workflow = yaml.safe_load(path.read_text())
        assert set(workflow['on']) == {'workflow_dispatch'}
        assert workflow['concurrency']['group'] == 'day37-aws-staging-exclusive'
        assert 'id-token' not in workflow['permissions']


def test_three_workflow_bash_syntax() -> None:
    for path in FILES:
        workflow = yaml.safe_load(path.read_text())
        for name, job in workflow["jobs"].items():
            for step in job["steps"]:
                if "run" not in step:
                    continue
                check = subprocess.run(["bash", "-n"], input=step["run"], text=True, capture_output=True, check=False)
                assert check.returncode == 0, (path.name, name, step.get("name"), check.stderr)
