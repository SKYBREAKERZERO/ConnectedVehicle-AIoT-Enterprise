# Replay acceptance

`tests/unit/simulators/test_replay_acceptance.py` checks real SQLite rows and transactions.

| Standard | Assertion |
| --- | --- |
| 1 | Selected A changes only state and retry due time. |
| 2 | B and C complete rows, commands and identity remain identical. |
| 3 | Original serialized payloads and SHA256 remain identical. |
| 4–6 | Missing or blank operation ID, actor or reason rejects without any table changes. |
| 7 | Duplicate operation changes zero rows and retains exactly one audit record. |
| 8 | Reused operation ID with different event, actor or reason conflicts without changes. |
| 9 | A real SQLite trigger rejects audit insertion after the event update; the whole transaction rolls back. |
| 10 | Foreign tenant scope rejects before both new and duplicate operations; an authenticated foreign principal cannot override scope. |
| 11 | Blocked or deferred ACK prevents claiming the terminal report; confirmed delivery releases it. |
| 12 | Closing and reopening the SQLite file preserves complete rows, binding, audit, idempotency and ACK ordering. |

Replay requires explicit tenant and vehicle scope matching the persisted device binding. Unbound legacy files reject replay until explicitly provisioned. Scope is checked inside the write transaction before looking up an idempotent operation. Runtime and maintenance ownership locks still apply.

The offline CLI is a host administrator tool: scope arguments and actor names are declarations, not authentication. Restrict access to the device database and maintenance shell. A future remote replay endpoint must authenticate and authorize the operator and derive scope from its verified identity. These tests establish the local ledger contract, not a deployed production identity provider.

Run:

```powershell
.\.venv\Scripts\pytest.exe tests/unit/simulators/test_replay_acceptance.py -q
```

Validation: all 15 dedicated acceptance cases passed. The complete unit, contract, independent-runtime E2E, device-chain E2E and PostgreSQL runtime-permission suite passed: 657 tests. Ruff check, Ruff format check, mypy, module contracts, Terraform recursive format check, local/dev validation and Git whitespace check passed.
