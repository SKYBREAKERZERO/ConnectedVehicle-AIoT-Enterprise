# Day31: CI identity binding and recovery admission

## Scope

This change rejects an unauthenticated/self baseline, binds two CI identities to
one candidate and rechecks local isolation under writer transactions. It remains
Dry Run Only. Successful tests or artifacts never grant deployment authority.
No production AWS credentials, Apply, State Push, Restore or Force Unlock are used.

There are three separate results: candidate policy tests, a read-only live API
inspection and a protected-main aggregation workflow. They are not interchangeable.
The new workflow cannot have an installed, protected-main execution until this PR
receives independent review and is merged. Before then the local inspector can
record CI identity matches, but `trusted_control_plane_installed=false` is an
unfulfilled trust condition. Its explicit `--inspect-uninstalled` option is local
audit only and is rejected as a qualification bypass on GitHub Actions.

## Event-bound baseline

Both IaC and Runtime use `scripts/iac/ci_baseline_policy.py`. Full Git history is
checked out. No zero-SHA fallback, HEAD fallback or symbolic baseline is accepted.

| Event | Required identity and history |
|---|---|
| PR | Exact repository/main target, PR merge ref, candidate parents equal event base/head, authoritative job SHA with matching Git parents, distinct ancestor base |
| Push | Existing, non-forced main push; before/after/ref match event and checkout; distinct ancestor before |
| Merge queue | Main queue ref, exact base/head SHA, ancestor base; no assumption that queue head is a single PR merge |
| Manual | Current main checkout only, first parent baseline, no input overrides; root/self/old-main candidate denied |

The cached PR payload `merge_commit_sha` cannot override the job SHA: mergeability
is computed in the background. The [REST API documentation](https://docs.github.com/en/rest/pulls/pulls)
describes that lifecycle. The live aggregator separately checks the current API
merge candidate and rereads it after inspection.

The Terraform gate also verifies the separate baseline checkout's real HEAD and
Git root against the event report. The gate copies the pinned commit through
`git archive`, so modified/untracked files in the sibling baseline working tree
cannot contaminate the comparison. Passing the candidate workspace as baseline
fails before external tools run. Runtime archives only the validated full SHA.

PR branch HEAD, PR merge candidate and a later main commit are separate identities.
GitHub's [event reference](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows)
defines their event-specific meanings. Baseline checks do not assert that a later
squash/rebase/main SHA equals an earlier PR merge SHA. Live aggregation currently
inspects current open PRs; other events have baseline contracts, not a claimed live
cross-workflow release attestation.

## Isolation and process ordering

Day29's initial receipt ownership and quarantine checks now take the same SQLite
writer lock. Inputs are copied before checking. Claim creation, Day27 transitions
and final Day29 ledger completion retain independent in-transaction rechecks.
ACTIVE and RECONCILED still retire the release ID. Read-only diagnostics are not
an execution permit; every actual status mutation checks under BEGIN IMMEDIATE.

Real independent-process tests exercise both orderings of revocation/admission:

- Revocation holds the writer lock first: subsequent admission is denied.
- Admission holds it first: its pre-revocation APPROVED commit may complete, then
  revocation commits and subsequent admission/read is denied. Neither ordering
  creates READY or another approval consumption.

The suite also reuses Day30's actual crash-after-VERIFIED, atomic audit failure,
RECONCILED replay, lost commit response, two-reconciler and bounded-lock exercises.
Existing records are preserved; there is no automatic reset, promotion or unlock.
These are local SQLite/process tests with synthetic identities and plans, separate
from the retained native Terraform/LocalStack gates. A shared DB outage can deny
all callers; this implementation does not guarantee availability during DB failure.

## Cross-workflow API inspection

`workflow_evidence_binding.py` makes GET requests only. It selects the latest Run
for each exact workflow/head/event, including pending/cancelled/failed results;
it never searches backwards for an older green Run. It requires each named quality
job to succeed in the current Run Attempt and compares both artifacts to the same
live PR merge candidate and its exact parents.

Artifact owner, name, expiry, timestamp, GitHub-reported ZIP SHA-256, member names,
size bounds, candidate/source hashes, Run/Attempt, JUnit and JSON digests must agree.
ZIP entries are read as bounded data in memory, never extracted or executed. Tokens
are stripped on artifact-host redirects. Signed URLs/credentials are not printed.
PR, latest Run identities and the active main ruleset are reread after downloads
to reject stale snapshots. The ruleset must retain independent review, both strict
Required Checks and no bypass actors.
There is no guarantee against changes *after* a successful snapshot; any future
execution service must revalidate immediately before acting.

The trusted job checks out `github.workflow_sha`, never a PR/trigger head. It uses
only contents/actions/pull-requests read permissions, no secrets input, deployment
Environment, package install from artifacts or `id-token: write`. PR contract jobs
are separate, low-privilege and explicitly not trusted-main execution. This follows
GitHub's [untrusted-code security guidance](https://docs.github.com/en/actions/reference/security/secure-use).

Main policies, host/database administrators, clocks and authentication adapters
remain trusted inputs. Matching API records/source hashes does not prove real AWS
identity, human recovery approval or independently trustworthy test assertions in
arbitrary PR code. The binder is CI identity/data integrity verification, not a
signed deployment capability; `release_authorized` and `apply_authorized` stay false.

## Mandatory flows and evidence

| Flows | Evidence |
|---|---|
| F01–F04 | Zero/self/unauthorized manual baseline and wrong merge identity unit refusals; real Git merge-graph integration |
| F05–F06 | Different candidate and newer cancelled Run with older green still present are rejected |
| F07–F08 | Real crash leaves VERIFIED/CLAIMED isolated; acknowledgement cannot revive it |
| F09 | Two real-process writer-lock orderings; no admission after committed revocation |
| F10 | Lost response uses durable lookup; two reconcilers and bounded lock failure do not reconsume |
| F11–F12 | Missing fault case, skipped/corrupt proof and another Run Attempt fail verification |

IaC uploads `day31-iac-trust` with event baseline, unit JUnit, fault JUnit/JSON and
governance JSON. Runtime separately uploads `day31-runtime-trust` after all Runtime
tests and prior acceptance checks. Each binds its own Run/Attempt to the same
candidate/source. `cross_workflow_binding_completed=false` in the IaC report is
intentional: neither workflow can declare that its still-running peer succeeded.
Aggregation occurs only after the pair can be inspected independently.

The protected-main job uploads a separate `day31-cross-workflow-binding` artifact
when installed and eligible. A first workflow completion while its peer is pending
fails closed; the later completion can inspect the finished pair. It does not
update PR checks or production permissions. Main installation and a real trusted
dispatch remain separate acceptance items, never inferred from a PR test pass.

Local reports/final downloaded acceptance are under `.runtime-reports/day31/`.
The user's existing Terraform edit, module lock files and untracked `test.tf`
remain outside this change. No Terraform resource type or Runtime migration is added.
