# Day37 AWS staging root — deliberately not activated

The `.tf.example` files describe the separate staging root. Its tested resource
blueprint is `../../modules/ota-staging`, including ECR, Fargate, internal TLS ALB,
security groups, IAM identities, encrypted logs and service failure rollback.

Do not rename these templates into active `.tf` files until protected-main
review, the Day36 supply gate, signed ECR manifest evidence, sandbox budget and
cleanup policy, State backend, and a read-only state-backed AWS plan gate exist.
The existing IaC gate intentionally rejects active AWS roots with resources
before that plan gate. Day37 preserves this protection; mock-provider plans are
contracts, not real AWS plans or deployment verification.

Inputs reference existing private VPC/subnets, DB/cache security groups, AWS
interface endpoints/S3 gateway, a private OIDC JWKS proxy, ACM certificate and
KMS policies. These dependencies are NOT created or verified by the blueprint.
PostgreSQL roles and tenant grants remain the trusted bootstrap/migration
responsibility. Only the application secret ARN goes into the task; no secret
value, bootstrap or migration credentials are embedded.

The initial `aws-staging` GitHub OIDC role is read-only. It cannot push ECR
images, update ECS, pass roles or retrieve application secrets. Real delivery
permissions, Sigstore verification and approval integration require a separate
reviewed change; Production's dry-run workflow remains unchanged.
