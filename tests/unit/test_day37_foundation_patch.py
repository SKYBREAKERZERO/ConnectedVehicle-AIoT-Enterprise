import importlib.util
from pathlib import Path
import pytest

SCRIPT=Path(__file__).resolve().parents[2]/'tools/patch_foundation.py'
spec=importlib.util.spec_from_file_location('p37',SCRIPT)
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

def fixture_hcl():
    return '''resource "aws_db_parameter_group" "postgres" {
  parameter {
    name  = "log_statement"
    value = "ddl"
  }
}
resource "aws_secretsmanager_secret" "application" { name = "example" }
resource "aws_secretsmanager_secret" "redis_auth" { name = "example2" }
'''

def test_tls_and_actual_rotation_resources():
    text=mod.patch(fixture_hcl())
    assert 'name  = "rds.force_ssl"' in text
    assert 'value = "1"' in text
    assert 'aws_secretsmanager_secret_rotation" "application"' in text
    assert 'aws_secretsmanager_secret_rotation" "redis_auth"' in text
    assert 'rotate_immediately  = false' in text
    assert 'default =' not in text
    assert 'checkov:skip' not in text

def test_double_patch_refuses():
    text=mod.patch(fixture_hcl())
    with pytest.raises(ValueError,match='already be present'):mod.patch(text)

def test_unknown_foundation_refuses():
    with pytest.raises(ValueError,match='contract changed'):mod.patch('invalid')
