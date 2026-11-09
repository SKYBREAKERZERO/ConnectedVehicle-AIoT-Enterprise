# Day39 Trusted Security Gate

Day37 starts its read-only Admission job before requesting any AWS OIDC token.
Admission runs the verifier at the exact protected `main` workflow SHA. The
repository, dispatch event, ref, workflow file, requested commit and Git
checkout must agree. The live `main` Ruleset and current HEAD are checked
before upstream evidence is considered. A PR run or a workflow observer
cannot supply the protected-main security result.

## Admission evidence

- Select the latest Day38 **push** run for that SHA by run creation time. A
  rerun of an older run cannot supersede a newer failure or cancellation.
- Check the exact Attempt through GitHub, require all Day38 jobs and security
  steps to have succeeded, and reject missing, expired or foreign artifacts.
  Verify the archive digests published by GitHub and the contents of the
  offline receipt, 22 sealed stages and 12 fault probes.
- Independently verify the latest Runtime final job and sealed
  `runtime-verified-evidence` archive. Check the Day35 decision, fault JUnit
  digest and Day34 receipt digest against the same Commit, Run and Attempt.
- Require all six Staging Environments to restrict deployments to the
  `main` branch, require a reviewer, prevent self-review and disallow admin
  bypass. Actual approval is enforced by GitHub at each Environment job.
- Recheck the latest upstream runs and current `main` before accepting.
  Record GitHub artifact IDs and ZIP digests in the same-run Day37 admission
  receipt. Final verification requires that receipt and its Day39 decision.

All eight Day37 OIDC jobs explicitly require a successful Admission job and
a dispatch on `main`, including emergency rollback inside the release DAG.
Security acceptance carries no AWS or production authorization. Environment
approval, OIDC and existing Terraform plan and apply controls remain separate.
The standalone recovery workflow is outside new-release admission and
retains its own reconciliation controls.

## Verification

```powershell
$env:PYTHONUTF8 = '1'
python -m pytest tests/unit -k 'day37 or day38 or day39' -q
actionlint -shellcheck= -pyflakes= .github/workflows/day37-aws-staging.yml
```

The Day37 source job records Day39 fault tests in a JUnit artifact named with
its commit, Run ID and Attempt. Those test reports are diagnostics. Release
admission uses the independently verified protected-main evidence above.

## Observed GitHub status

The local change is based on PR #18 commit
`d81bc3675c001d3ba6a8275ef6517ae0024d6cae`. Day38 run
[42446146469](https://github.com/SKYBREAKERZERO/ConnectedVehicle-AIoT-Enterprise/actions/runs/42446146469)
failed Checkov rule `CKV2_AWS_57` for the application and Redis Secrets Manager
resources. The live repository listed only the `production` Environment
during the audit. Live Day39 admission remains blocked until reviewed code
is on protected `main`, the required same-SHA CI evidence passes, and the
Staging Environments can be verified. No AWS credential or apply is needed
for the local tests.
