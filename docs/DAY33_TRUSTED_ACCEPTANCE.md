# Day33 Trusted Acceptance

## Confirmed cause

Run 41261479939 Attempt 13 Native job 124846736007 was cancelled by GitHub concurrency scheduling. The check annotation says: `Canceling since a higher priority waiting request for iac-15 exists`. The actual Terraform step ran from 12:22:24 to 12:24:30 UTC on 2026-11-01, below its 30-minute job timeout. This is evidence of concurrency cancellation, not a Terraform validation failure or a timeout. Actor/initiator of the higher-priority request is not established by that annotation.

Raw API records, annotations and failed logs are retained under `.runtime-reports/day33/` (local, ignored).

## Change and verification

The existing per-PR concurrency group remains; `cancel-in-progress: false` lets an active Native execution finish. GitHub may still replace pending requests, users can explicitly cancel, and job timeouts still apply. This is not a guarantee that every queued run executes. Latest candidate/run/attempt eligibility remains mandatory; historical green reports cannot substitute for the latest cancelled or failed attempt.

`scripts/iac/day33_independent_verifier.py` validates completed successful latest run identity, all 13 successful distinct jobs including the final gate, server ZIP digest/owner/time, exact acceptance members, report proof hashes and candidate/run/attempt bindings. Its offline CLI expects separately collected API records and does not authenticate those records by itself. The read-only live collection must supply GitHub API records, compare the PR merge parents, download the full sealed bundle, and recompute existing pipeline and Day32 evidence using exact candidate source. The presentation ZIP alone is insufficient for full JUnit/source validation.

Negative tests cover cancelled/skipped/missing jobs, old attempts, wrong candidate head, modified ZIP bytes, missing artifact members and old artifact identity. These are controlled unit fixtures, not claims of real AWS execution or independent human approval.

## Final Gate boundary

PR #15 still requires a real independent non-author review. No independent approval, protected merge, trusted-main promotion, production credentials or production deployment is implied by successful LocalStack evidence. Final release authority remains denied. No AWS Apply, production State Push, Restore or Force Unlock is enabled.

## Reproduce

```powershell
python -m ruff check scripts/iac tests/unit/iac tests/integration/iac
python -m ruff format --check scripts/iac tests/unit/iac tests/integration/iac
python -m mypy scripts/iac
python -m pytest -c scripts/iac/pytest.ini tests/unit/iac -q
python -m scripts.iac.day33_independent_verifier --directory <downloaded-audit-directory>
```

The API collection directory must contain `context.json`, `run.json`, `jobs.json`, `artifact.json`, `acceptance.zip`. `context.json` freezes `head_sha`, `candidate_sha`, `latest_attempt`; retrieve latest API metadata again after downloads to detect a concurrent rerun. No report should be called PASS until the complete same-attempt bundle verifies.
## Baseline execution observed on 2026-11-02

Run 41261479939 Attempt 14 completed successfully at head `0a84d390fa7636ab1f0bb2d0027068b557c91c91` (PR merge candidate `74ca065afbceea59fce48953b0ca0787f623490d`). All 13 jobs passed, including 104 Terraform contracts across 17 roots, LocalStack deployment and six live service checks. The current-attempt presentation ZIP and complete evidence ZIP were independently downloaded, their GitHub SHA-256 digests verified, and pipeline/Day32 evidence recomputed from the exact candidate archive. No old Attempt was used as a replacement. This baseline predates the Day33 concurrency change; the new commit requires its own CI run.

Local Day33 checks passed: 707 IaC unit tests (15 Day33 tests), Ruff, formatting, Mypy, actionlint on the modified workflow, and whitespace checks on changed files. Runtime and real AWS are not implied by these local results. The final run-specific acceptance, ZIP audit and release decision are retained under `.runtime-reports/day33/`.
