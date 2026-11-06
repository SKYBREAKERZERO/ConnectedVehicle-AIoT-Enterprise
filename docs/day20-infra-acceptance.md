# Day20 infrastructure acceptance scope

Governance: native mocked contracts, provider schema inspection, an independently planned offline root, firmware version delete protection, Key Policy freeze, dedicated OU scope checks and a controlled retirement reviewer. Real Organizations account moves, inherited permission enforcement and real AWS operations are not executed.

State backend: local bootstrap with a protected KMS key, explicit local account key policy, versioned encrypted private state storage, and no completed-version expiry. Remote backend migration, Import and Drift exercises are separate unfinished work; an init/validate is not evidence of migration or recovery.

OTA local gate: creates isolated IAM/Secret fixtures, plans and applies OTA modules only in an ephemeral loopback LocalStack container, evaluates resolved security policies, and requires the second plan to have no changes. It does not read private Terraform variables or developer State. Existing platform baseline comparison and zero-destroy checks remain enabled. It proves neither API-to-device E2E completion nor IAM/SCP authorization enforcement.

Scanner: the inherited local bootstrap trust/DB rotation exceptions remain narrowly scoped. New local-only exceptions for S3 logging, notifications and cross-region replication plus OTA authority auto-rotation expire on 2026-11-18. They match exact resource/path/check identities and require Environment=local. They are not valid for dev/prod or for encryption, public access, wildcard Allow permissions, parsing errors, skips, deletion or replacement. Expiration and scope escape are regression-tested. These operational integrations must be completed before a cloud readiness claim. No completed object versions are expired by the added multipart-cleanup rules.

Evidence: CI summary reports test counts, zero destroy actions, repeat-plan result and the explicit unverified Organizations enforcement flag. Review the PR commit and exact workflow runs; old main workflow successes are not evidence for this change.
