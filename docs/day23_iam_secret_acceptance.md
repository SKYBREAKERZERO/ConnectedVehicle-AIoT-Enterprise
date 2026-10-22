# Day23 — OTA database credential IAM isolation

## Scope and findings

The OTA root previously attached `module.database_read_policy` to both the API
role and Campaign role. Role names were distinct, but either role could read the
application database secret. This change preserves the API policy address and
introduces a separate Campaign policy using the existing IAM policy module.
No AWS resource types, provider locks or database migrations are added or changed.

The root is restricted to LocalStack: `environment=local`, account `000000000000`
and an explicitly local endpoint. It is not a production deployment root.

## Permission matrix

| Permission owned by this root | API role | Campaign role |
| --- | --- | --- |
| Read application database secret | Allow exact API ARN | No grant |
| Read Campaign database secret | No grant | Allow exact Campaign ARN |
| Decrypt API database credential | API key, API SecretARN context | No grant |
| Decrypt Campaign database credential | No grant | Campaign key, Campaign SecretARN context |
| Read approved firmware objects | Existing exact object policy | Existing exact object policy |
| Read tenant OTA authority | Existing authority policy | Existing authority policy |
| Change database credentials | No grant | No grant |

Both decrypt statements require `kms:ViaService` to equal the configured regional
Secrets Manager service and `kms:EncryptionContext:SecretARN` to equal the owning
runtime's secret. Separate database KMS inputs permit distinct keys, but sharing
the existing database key is allowed: the exact encryption context separates the
grants. Artifact and authority keys remain distinct, unchanged.

API artifact access is used in `apps/api/routers/ota_execution.py` and
`apps/api/routers/ota_campaign.py`; Campaign uses `ArtifactVerifier` in
`apps/campaign/__main__.py`. Both services retain their existing transition or
Campaign authority dependency in `connected_vehicle/ota/execution_service.py`
and `connected_vehicle/ota/campaign_service.py`. This change does not expand either
existing authority/artifact policy.

## Required inputs and deployment boundary

Supply `campaign_database_secret_arn` and `campaign_database_kms_key_arn` explicitly;
there is no fallback to the application secret. Equal database Secret ARNs fail
Terraform variable validation. Equal runtime roles fail lifecycle preconditions.
Invalid Campaign secret accounts/regions and invalid KMS regions are rejected.
The existing `runtime_read_policy_arns` output remains the API policy map;
`campaign_read_policy_arns` reports the Campaign module's actual attachments.

The root references existing database secrets. A trusted database bootstrap must
provision and maintain the Campaign credential and PostgreSQL role/GRANT. It must
not copy the API username/password into another secret and call that isolation.
Terraform does not inspect secret values, create database users or prove database
authorization. The ephemeral CI fixture creates two empty Secret metadata objects
solely to test AWS resource wiring; it is not database credential evidence.

Runtime currently calls `load_runtime_database_settings(settings, "application")`
and verifies the `application` identity in `apps/campaign/__main__.py`. This IaC
change does not alter that application contract. A dedicated PostgreSQL identity,
trusted bootstrap, Campaign configuration and real PostgreSQL authorization tests
are required before claiming end-to-end credential isolation or deploying this
changed role to a running Campaign worker.

The IAM assertions cover policies/attachments managed by this root. The existing
API role may have externally managed inline/attached policies; these must also be
audited before asserting effective AWS access denial. LocalStack wiring tests are
not production IAM authorization evidence.

Existing OTA deployments will replace the Campaign database policy attachment
when switching to the new policy ARN. The no-destroy plan gate remains intact
and rejects such replacement unless handled through a separately reviewed
migration procedure; no deletion exception or automatic live migration is added.
The current PR baseline has no OTA root, so CI exercises creation from that base.

## Verification and evidence

- `terraform init -lockfile=readonly`, `validate` and native `test` in the OTA root.
- Nine native runs: existing composition, isolated credentials/bindings/KMS
  contexts, shared secret rejection, shared role rejection (including IAM case variants), nonlocal environment,
  remote endpoint, wrong secret account and wrong KMS region rejection.
- IaC policy regression tests include cross-secret reads, cross-role attachment,
  broad key decrypt, missing ViaService, wrong encryption context, write grants,
  extra statements, malformed evidence, and shared identity configuration.
- The IaC gate resolves the real LocalStack deployment's second plan, checks the
  exact two credential policy documents and exclusive owning-role attachments,
  and fails on missing or malformed evidence. Existing scans, contracts,
  checksums, baseline checks and zero-change second plan remain mandatory.
- Repository Ruff, format, Mypy and IaC pytest checks run locally. GitHub Runtime
  remains required for full Runtime and real PostgreSQL regression evidence.
- Final run IDs, commit SHA and downloaded CI summaries belong in the ignored
  `.runtime-reports/day23/` directory, avoiding a documentation-only commit that
  would invalidate the SHA being accepted. Both required PR checks must succeed
  on the same delivered commit before Day23 CI acceptance is claimed.

No production AWS apply, GitHub merge, database DDL, or provider checksum bypass
is authorized by this work. LocalStack applies operate only in isolated gate
fixtures with dummy credentials and copied state.
