# IaC quality gates

The GitHub Actions workflow runs for every pull request to main, merge queue, main
push and manual dispatch. It has no path filter, no soft-fail and no production AWS
credentials. Its stable required-check name is **IaC quality gate**.

The gate runs:

1. Policy regression tests, lint, formatting and strict type checks for gate code.
2. Terraform fmt and validation for every environment and module, with committed
   provider locks. Every module must have native `.tftest.hcl` contract tests.
   Contract tests use mocked AWS providers, cover both SQS encryption modes, redrive,
   IAM trust/boundaries, CMK rotation, secret recovery and runtime Secret isolation,
   including expected failures for invalid inputs.
3. Checkov across both the deployment source (including its tfvars) and the isolated CI fixture. Parsing errors, zero checks,
   inline skip directives, unapproved findings and expired exceptions fail CI.
4. An ephemeral LocalStack seeded from the PR base commit (previous commit for main
   pushes). The candidate plans against that copied baseline state. Any delete,
   replacement or state-removal action fails, including zero-create/all-destroy plans.
5. A candidate apply exclusively in that emulator, followed by a resolved JSON plan
   policy check and a second plan requiring exit code 0. The full policy checks
   unchanged resources too, so a no-op plan cannot hide unsafe existing policies.

ARNs can be unknown before creation. Only the emulator's pre-apply **changes** phase
accepts them; the **resolved** policy phase fails closed on unknown security fields.
Never use `--phase changes` as an AWS deployment approval. The candidate plan is
applied only after static scanning and deletion checks pass. The emulator has fake
credentials, no Docker socket mount and no persisted volume; it is removed on success
or failure. Existing development containers, state and credentials are never used.

The policy blocks Allow Action/Resource/Principal wildcards (including partial `*`
and `?`), NotAction/NotResource/NotPrincipal, public trust, unverified external policy
attachments and missing encryption. A Deny wildcard is permitted. The only broad
KMS statement allowed is AWS's canonical account-root delegation in the policy of
that exact key: `kms:*`, Resource `*`, and the key's own account root. KMS Resource
`*` means that key, so this exception never applies to IAM identity policies.

IAM policy descriptions are immutable AWS metadata. The IAM module ignores only
changes to an existing policy description, avoiding forced policy/attachment
replacement when improving explanatory text. Names, permissions documents and all
security attributes remain checked. New policies use the requested description.

Encryption rules cover SQS, Secrets Manager, SNS, RDS, EBS, EFS, DynamoDB and S3.
New resource types fail until reviewed policy support is added. KMS rotation must
be enabled. The local root now enables it by default. Existing explicit local tfvars
remain under the operator's control; the gate uses stable test variables rather than
local tfvars. When adding a non-local environment with resources, CI fails until a
read-only, state-backed AWS plan gate is implemented. The current dev root is only
a provider scaffold; this workflow does not claim to validate live AWS state/drift.

## Scanner exceptions

`scan_exceptions.json` contains four exact-resource exceptions expiring 2027-01-01:
LocalStack account-root bootstrap trust (CKV_AWS_61) and automatic rotation of the
three LocalStack PostgreSQL secrets (CKV2_AWS_57). Their reasons are recorded in the
file. The bootstrap trust is still checked by the resolved plan policy. Controlled
provisioning handles local secret rotation; production automatic rotation remains
required design work. No waiver is accepted for wildcard IAM, encryption or destroy
policies. Exceptions cannot be global scan skips or apply to an AWS root.

## Run locally

Use Python 3.12, Terraform 1.14.7, Docker and the isolated tooling environment:

```powershell
python -m venv .venv-iac
.venv-iac\Scripts\python -m pip install -r scripts/iac/requirements.txt
.venv-iac\Scripts\python -m pytest -c scripts/iac/pytest.ini tests/unit/iac -q
.venv-iac\Scripts\python -m scripts.iac.gate --baseline D:\path\to\base-checkout
```

The baseline must be the actual target commit for meaningful deletion detection.
For a local smoke test, `--baseline .` seeds and compares the current configuration.
The runner allocates a temporary directory and copies only IaC source and provider
locks, excluding local state/tfvars. CI uses separate checkouts for baseline and the
candidate merge result. Tool versions, action commits, provider versions and the
public LocalStack test-image digest are pinned. No paid LocalStack token is needed.
Only the sanitized success summary is uploaded; raw plans, state and scanner source
snippets are not published as CI artifacts.

## Enforce on main

A failing workflow blocks merges only when GitHub branch protection/rulesets require
its check. `.github/CODEOWNERS` assigns the repository owner to workflows, policy
code, exceptions, Terraform and policy tests. Review ownership if moving to an org.
Ensure IaC quality gate has run at least once, then use a repository administrator:

```powershell
gh auth login
python -m scripts.iac.protect_main --repo SKYBREAKERZERO/ConnectedVehicle-AIoT-Enterprise
python -m scripts.iac.protect_main --repo SKYBREAKERZERO/ConnectedVehicle-AIoT-Enterprise --apply
```

The first command previews the exact update. The second applies it: existing required
checks/reviewer counts/restrictions are preserved; the IaC check is bound to the
GitHub Actions app, up-to-date branches and owner review are required, stale reviews
are dismissed, the last push needs approval, administrators are enforced, and force
pushes/deleting main are disabled. GitHub credentials and admin access are required.
The script does not publish code, create a PR or grant itself privileges. Repository
plan restrictions may affect availability of protected branches for private repos.
Until the workflow is pushed and that remote rule enabled, these are local checks,
not a claim that main is already protected.

Native test mocking: [HashiCorp documentation](https://developer.hashicorp.com/terraform/language/tests/mocking).
Scanner fail/skip controls: [Checkov CLI documentation](https://www.checkov.io/2.Basics/CLI%20Command%20Reference.html).
