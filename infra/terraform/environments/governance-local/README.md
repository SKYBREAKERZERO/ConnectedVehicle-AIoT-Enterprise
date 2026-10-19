# Offline governance integration root

This root calls the actual OTA governance module with illustrative dev/prod account IDs, separate firmware/state buckets and KMS protection. All IDs are fake. Management is hardcoded off and the mode is offline. Changing those constants requires a separate review; no existing OTA/application runtime identity is used for organization administration.

The IaC gate initializes a disposable copy with a validated local backend, validates it, runs its native mocked root test and requires a zero-resource plan. Module native tests additionally exercise explicit localstack-mode topology/enforcement contracts through a mocked provider. Neither proves real OU inheritance authorization or AWS/LocalStack SCP enforcement. Actual permission acceptance must include restricted member-role positive/negative requests and remain recorded as unverified until run.

Free LocalStack 3.8.1 is used by the separate OTA storage acceptance path. Organizations enforcement is not required or claimed for that image. Real AWS deployment is outside this local task.
