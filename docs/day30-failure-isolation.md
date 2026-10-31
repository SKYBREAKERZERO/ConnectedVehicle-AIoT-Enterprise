# Day30: persistent local failure isolation

## Result and trust boundary

A failure in one recovered release now blocks that release through the actual
Day27 and Day29 admission APIs. It does not reset approval consumption, overwrite
another release, repair State or authorize deployment. Day27's existing state
enumeration is unchanged. Day30 stores its governance decision separately.

The implementation is still a trusted, single-host SQLite demonstration. Local
operators, bootstrap identity adapters, database files and the host are trusted.
These APIs are not an unauthenticated network service. They do not establish real
GitHub/AWS identity, central cross-runner coordination or immutable external audit.
An outage of the shared database may deny all callers; isolation does not promise
availability when the database itself cannot be read or written.

## Durable isolation

`scripts/iac/failure_isolation.py` creates `day30_quarantine` and `day30_audit` only
in a purpose-marked IaC governance DB. Quarantine has one immutable operation ID
per release, a unique release ID, receipt hash, reason, observed Day27/29 states,
evidence hash, ACTIVE/RECONCILED status and timestamps. Quarantine and its audit
event are committed in one transaction. An injected audit failure must roll back
both. A repeated call or two competing reconcilers cannot create a second event.

Scanning defaults to read-only classification. It does not update Day27, Day29,
approvals, registry versions, reservations or State. A CLAIMED row may be an active
operation, so an operator must quiesce the affected worker before explicitly
quarantining a partial commit; the scanner does not guess that a worker is dead.

An explicit acknowledgement changes only Day30 to RECONCILED and records a second,
idempotent audit action. It acknowledges the classification, not successful repair.
The release ID remains retired. No API clears quarantine, resets a claim, reuses a
receipt or promotes a release to VERIFIED/READY.

## Actual admission enforcement

- Day27 `request`, `state`, every `advance` target and `interrupt` query isolation.
  Mutations recheck under BEGIN IMMEDIATE. Diagnostic scans are deliberately not
  an admission API. Stateless Plan validators alone cannot authorize a release.
- A Day27 VERIFIED row with Day29 CLAIMED is denied even before an operator writes
  quarantine. The legitimate in-flight REQUESTED-to-VERIFIED transaction retains
  its existing trusted Day29 callback; further promotion cannot use that window.
- Day29 checks before verification, inside claim creation and before its final
  ledger commit. It rechecks current receipt and registry bindings under the lock.
  Deterministic failure no longer overwrites Day29 status after an exception;
  partial/ambiguous original records are preserved and isolated instead.
- Approval validation and read-only lost-response lookup reject receipts linked
  to a quarantined release. Recovery requests cannot use a quarantined origin.
  A losing competitor cannot quarantine the winning release or its receipt.
- Signed/registered State relationships are matched by exact record digest,
  backend scope, VersionId, lineage and serial. Superseded/revoked versions,
  revoked/expired approval and binding substitutions deny related admission.
  Explicit quarantine affects one ID; other affected IDs appear separately in
  the scan and unrelated bindings remain eligible.

Authenticated preflight failures reserve only a previously unowned release ID.
Plan hash mismatch and drift have distinct reason codes. An invalid actor/forged
receipt cannot poison an ID. No automatic retry creates another release request.

## Bounded locks and unknown commits

Quarantine/acknowledgement retry only BEGIN acquisition: three attempts, each with
a 50 ms SQLite timeout and 20/40 ms backoff. Writes and commits are never retried.
If commit returns an error, close the connection and query the stable operation
ID. A confirmed persisted result is returned; an unconfirmed result raises
`IsolationUnavailable` with the operation ID. If the DB stays locked, no durable
quarantine can be promised; admission still fails closed and an operator must
perform read-only lookup and reconciliation after access returns.

Approval response loss uses the existing authenticated `recover_consumed` query.
It never calls consume again. Receipt uniqueness and durable claims are retained
after crashes. There is no automated timeout-based reset or force-unlock.

## Operator commands

Use only an isolated governance DB, never the Runtime business database:

```powershell
# Default mode opens SQLite read-only and does not even create isolation tables.
python -m scripts.iac.failure_isolation --database <governance.sqlite>
# Explicit trusted local operation after quiescing this worker and reviewing scan.
python -m scripts.iac.failure_isolation --database <governance.sqlite> --quarantine <release-id>
# Acknowledge classification; admission remains blocked.
python -m scripts.iac.failure_isolation --database <governance.sqlite> --acknowledge <operation-id>
```

## Tests and CI evidence

`tests/integration/iac/test_day30_failure_isolation.py` contains the six required
cases: crash after Day27 VERIFIED, two reconcilers, actual admission blocking,
unrelated-release isolation, unknown commit/response loss and no promotion during
reconciliation. These use real independent Python processes and SQLite
transactions, with synthetic State/Plan/identity fixtures. They do not claim cloud
identity or real AWS recovery. Existing Day29 native Terraform/LocalStack and
Day27/28 failure probes remain separate mandatory gates.

The six scenarios record database counts, rollback outcomes, denied entry names,
original-row comparisons and process outcomes in `day30-faults.json`. Evidence
derives safety fields from those measurements, requires complete non-skipped XML,
and binds test-time Commit, Run/Attempt and source digest. Unit regressions include
bounded locks, exact State relationships, ownership, loser isolation, CLI read-only
behavior and missing/failed/replayed/ineffective evidence.

CI runs Day29 first, Day30 process tests next, then verifies Day30 evidence.
`day30-failure-isolation` uploads sanitized governance JSON, full unit JUnit and
fault JSON/JUnit for seven days. No raw State, binary Plan, database or credentials
are uploaded. Formal remote acceptance requires both quality gates on the same
commit and independent verification of downloaded evidence against committed
source. Local reports and final acceptance are under `.runtime-reports/day30/`.

Production AWS credentials, production Apply, State Push and Force Unlock remain
unused. Terraform modules and Runtime migrations are unchanged; the user's local
Terraform edit remains outside this delivery.
