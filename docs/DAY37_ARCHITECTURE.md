# Day37 P1 Architecture — fail-closed AWS staging

`Day36 same-commit evidence → Day37 admission → ECR publish/verify → Deploy Plan (READ) → separate GitHub Environment APPROVAL (exact SHA) → Apply exact versioned SSE-KMS Plan → ECS per RUNNING Task imageDigest + ALB → zero Terraform drift → close durable S3 fence → independent final gate.`

Bootstrap similarly uses separate `plan → approve → apply` Jobs, while cloud Foundation is a distinct Terraform state controlled by an infrastructure administrator. `aws-staging-recovery` Role is the sole fence-closing identity. A failed/cancelled deploy leaves the fence and blocks the next publication. Manual `day37-reconcile.yml` only clears after verifying old signed ECR digest and Terraform zero drift; it never applies a plan or downgrades PostgreSQL.

This code does **not** claim that Cloud AWS, PostgreSQL RLS, OIDC or actual ECS deployment tests have succeeded.
