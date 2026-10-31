# CI trust and permission remediation

## Closed in code; execution must still be checked

- The shared Runtime runner defaults to `app_user` with no provisioned implicit password. Scoped runtime credentials continue to come from the existing per-runtime/per-tenant secret flow. A real PostgreSQL authentication probe must see InvalidPasswordError, not connection refusal or timeout. Bootstrap and migration secrets exist only on their two explicit management steps, never the pytest/evidence steps.
- The credential contract follows runtime.yml into runtime-core.yml. It enforces the default identity and exact management-step allowlist; it cannot silently inspect the old workflow layout.
- pytest-asyncio explicitly uses function fixture-loop scope. This records the existing effective default instead of suppressing warnings.
- Cross-workflow selection orders same-Run snapshots by Attempt as well as creation time and Run ID. Failure, cancellation and pending reruns cannot fall back to a green first Attempt. Reports and artifact creation time remain bound to the latest Attempt.

## Isolated Actions fault matrix

`ci-fault-matrix.yml` calls `ci-fault-case.yml` for both Runtime and IaC scopes with five faults: producer failure, scheduler skip, absent artifact, changed artifact bytes and stale Attempt. Every case uses the actual production needs/bundle checker. Failure allowances exist only in this negative-test harness: the oracle independently requires the expected producer result, consumer failure and exact failing step. Oracle failure is never allowed. Production ci.yml/runtime.yml and their reusable engines retain their fail-closed policy and have no failure allowances.

Result artifacts carry Commit, Run, Attempt and raw scheduler outcomes. Attempt-suffixed names retain history without replacing earlier artifacts. A rerun must produce a fresh result; old results cannot be relabeled.

This is representative boundary injection, not exhaustive injection into all 18 production jobs. Actual run cancellation remains a separate manual exercise: the probe has read-only permissions and cannot cancel other workflows. Unit coverage exercises cancelled results. Real AWS, production deployment interruption and cross-account failure are not certified here.

## Open review and control-plane boundary

PR #15 can be marked ready after the candidate checks pass. The repository currently lists only SKYBREAKERZERO, also the PR author. That account cannot provide independent approval. No self-approval, bypass, direct main push or automatic merge is permitted.

The protected-main Day31 collector remains pending installation through independent review and merge. Its PR policy job and local --inspect-uninstalled API inspection do not close this requirement. After installation, run the collector from main against a fresh open PR, verify the latest IaC/Runtime Run/Attempt, exact merge parents and artifact hashes, and retain day31-cross-workflow-binding. A local PASS must not be substituted for that execution.

## Real AWS release boundary

Dry Run Only remains intentional. No production AWS credentials, Apply, State Push/Restore or Force Unlock are used. Before a real sandbox deployment, independently establish budget/cleanup controls, OIDC/STS identity, least-privilege roles, approval protections, encrypted/versioned/locked backend, saved-plan binding and recovery evidence. LocalStack success does not fulfill those checks.

## Acceptance

Record actual candidate SHA, Run IDs/Attempts, oracle reports and required-check conclusions after CI. Code changes or test counts alone do not close any runtime or trusted-main acceptance item.
