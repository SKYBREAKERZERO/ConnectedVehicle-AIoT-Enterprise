"""Offline Day20 source/coverage sanity check. NOT a Terraform HCL parser or AWS test.

Can be executed inside either the overlay package or an installed project checkout.
"""

from __future__ import annotations

import argparse
from pathlib import Path

MODULES = (
    "ota-governance",
    "ota-artifact-bucket",
    "ota-artifact-policy",
    "ota-runtime-iam",
    "ota-secrets",
)


def block_balance_hcl(source: str) -> None:
    """Conservative delimiter/quote sanity check, ignoring strings and comments."""
    stack: list[tuple[str, int]] = []
    pairs = {"}": "{", "]": "[", ")": "("}
    in_string = False
    in_comment = False
    escaping = False
    line = 1
    i = 0
    while i < len(source):
        c = source[i]
        if c == "\n":
            line += 1
            in_comment = False
            i += 1
            continue
        if in_comment:
            i += 1
            continue
        if in_string:
            if escaping:
                escaping = False
            elif c == "\\":
                escaping = True
            elif c == '"':
                in_string = False
            i += 1
            continue
        if c == '"':
            in_string = True
        elif c == "#" or source[i : i + 2] == "//":
            in_comment = True
        elif c in "{[(":
            stack.append((c, line))
        elif c in "}])":
            assert stack and stack[-1][0] == pairs[c], f"Unbalanced closing {c} at line {line}"
            stack.pop()
        i += 1
    assert not in_string, "Unterminated quoted string"
    assert not stack, f"Unclosed HCL delimiter(s): {stack}"


def verify(root: Path) -> list[str]:
    paths = []
    tf = root / "infra" / "terraform"
    is_overlay = (root / "INSTALL_DAY20.ps1").is_file()
    for module in MODULES:
        mod = tf / "modules" / module
        assert mod.is_dir(), f"Missing module {mod}"
        assert (mod / "tests" / "contracts.tftest.hcl").is_file(), (
            f"Missing native module test: {module}"
        )
        if not is_overlay or module in {"ota-governance", "ota-secrets"}:
            assert (mod / "versions.tf").is_file(), (
                f"versions.tf required for existing gate module enumeration: {module}"
            )
        for p in sorted(mod.rglob("*.tf")) + sorted(mod.rglob("*.tftest.hcl")):
            block_balance_hcl(p.read_text(encoding="utf-8"))
            paths.append(p.as_posix())

    bootstrap = tf / "bootstrap" / "state-backend" / "tests" / "contracts.tftest.hcl"
    assert bootstrap.is_file(), "Missing bootstrap test"
    block_balance_hcl(bootstrap.read_text(encoding="utf-8"))
    paths.append(bootstrap.as_posix())

    gov = tf / "modules" / "ota-governance"
    main = (gov / "main.tf").read_text(encoding="utf-8")
    locals_ = (gov / "locals.tf").read_text(encoding="utf-8")
    variables = (gov / "variables.tf").read_text(encoding="utf-8")
    output = (gov / "outputs.tf").read_text(encoding="utf-8")
    native_tests = "\n".join(
        p.read_text(encoding="utf-8") for p in (gov / "tests").glob("*.tftest.hcl")
    )

    checks = (
        ('policy_type.type == "SERVICE_CONTROL_POLICY"', main),
        ("count = local.enforcement_enabled ? 1 : 0", main),
        ("for_each = local.scp_targets", main),
        ("depends_on = [terraform_data.management_guard]", main),
        ('var.governance_stage == "enforce"', locals_),
        ("local.enforcement_enabled", locals_),
        ('default     = "topology"', variables),
        ('default     = "offline"', variables),
        ('default     = "ou"', variables),
        ("protected_firmware_bucket_arns", variables),
        ("protected_state_bucket_arns", variables),
        ('"s3:DeleteObjectVersion"', locals_),
        ('"kms:PutKeyPolicy"', locals_),
        ("local.protected_firmware_bucket_arns", locals_),
        ("local.protected_firmware_object_arns", output),
        ('run "offline_by_default_no_organizations_resources"', native_tests),
        ('run "firmware_objects_are_protected_but_state_objects_are_not"', native_tests),
    )
    for needle, haystack in checks:
        compact_needle = "".join(needle.split()).replace(",", "")
        compact_source = "".join(haystack.split()).replace(",", "")
        assert compact_needle in compact_source, f"Missing key Day20 guard/test: {needle}"

    artifact_policy = (tf / "modules" / "ota-artifact-policy" / "main.tf").read_text(
        encoding="utf-8"
    )
    assert "s3:GetObjectVersion" in artifact_policy
    assert "DenyExplicitWrongEncryption" in artifact_policy
    assert "DenyExplicitWrongKmsKey" in artifact_policy
    assert '"s3:x-amz-server-side-encryption" = "false"' in artifact_policy

    secrets_main = tf / "modules" / "ota-secrets" / "main.tf"
    if secrets_main.is_file():
        sec = secrets_main.read_text(encoding="utf-8")
        assert 'resource "aws_secretsmanager_secret_version"' not in sec, (
            "Do not put OTA authority secret value in Terraform State"
        )

    docs = [
        root / "docs" / "DAY20_INFRA_COVERAGE.md",
        root / "docs" / "DAY20_OTA_RUNTIME_ACCESS_MATRIX.md",
        root / "docs" / "DAY20_ACCEPTANCE.md",
    ]
    for doc in docs:
        assert doc.is_file(), f"Missing Day20 documentation: {doc}"
        paths.append(doc.as_posix())

    return paths


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    seen = verify(args.root.resolve())
    print(f"Day20 offline source sanity: PASS ({len(seen)} files checked)")
    print("Scope: file presence, delimiter balance, conservative security checks only.")
    print("NOT VERIFIED: Terraform fmt/validate/test, Checkov, CI, LocalStack or AWS runtime.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
