#!/usr/bin/env bash
# Staging Terraform helper. Never invokes Apply. Apply is explicit in the gated workflow.
set -euo pipefail
ROOT="${DAY37_TF_ROOT:-infra/terraform/environments/ota-staging}"
AWS_REGION='ap-northeast-1'
command="${1:-}"
case "${command}" in
  init)
    : "${DAY37_BACKEND_BUCKET:?reviewed staging State bucket required}"
    : "${DAY37_BACKEND_KEY:?reviewed staging State key required}"
    : "${DAY37_BACKEND_KMS_ARN:?reviewed staging State KMS key required}"
    : "${DAY37_ACCOUNT_ID:?exact staging account required}"
    [[ "${DAY37_BACKEND_KEY}" == connected-vehicle/ota-staging/* ]] || { echo 'BLOCKED: non-staging State key'; exit 1; }
    [[ "${DAY37_BACKEND_BUCKET}" == *staging* ]] || { echo 'BLOCKED: non-staging State bucket'; exit 1; }
    [[ "${DAY37_BACKEND_KMS_ARN}" == "arn:aws:kms:${AWS_REGION}:${DAY37_ACCOUNT_ID}:key/"* ]] || { echo 'BLOCKED: foreign State KMS key'; exit 1; }
    [[ "${TF_VAR_aws_account_id:-}" == "${DAY37_ACCOUNT_ID}" ]] || { echo 'BLOCKED: Terraform account mismatch'; exit 1; }
    CALLER_ACCOUNT="$(aws sts get-caller-identity --region "${AWS_REGION}" --query Account --output text)"
    [[ "${CALLER_ACCOUNT}" == "${DAY37_ACCOUNT_ID}" ]] || { echo 'BLOCKED: AWS STS account mismatch'; exit 1; }
    aws s3api head-bucket --bucket "${DAY37_BACKEND_BUCKET}" --expected-bucket-owner "${DAY37_ACCOUNT_ID}" >/dev/null
    STATE_VERSIONING="$(aws s3api get-bucket-versioning --bucket "${DAY37_BACKEND_BUCKET}" \
      --expected-bucket-owner "${DAY37_ACCOUNT_ID}" --query Status --output text)"
    [[ "${STATE_VERSIONING}" == Enabled ]] || { echo 'BLOCKED: State S3 bucket versioning disabled'; exit 1; }
    terraform -chdir="${ROOT}" init -input=false -lockfile=readonly -reconfigure \
      -backend-config="bucket=${DAY37_BACKEND_BUCKET}" \
      -backend-config="key=${DAY37_BACKEND_KEY}" \
      -backend-config="region=${AWS_REGION}" \
      -backend-config="kms_key_id=${DAY37_BACKEND_KMS_ARN}"
    ;;
  verify-release)
    : "${DAY37_ACCOUNT_ID:?staging account required}"
    : "${DAY37_ECR_REPOSITORY:?staging ECR repository required}"
    : "${2:?release.json required}"
    ECR_REGISTRY="${DAY37_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
    aws ecr get-login-password --region "${AWS_REGION}" | docker login --username AWS --password-stdin "${ECR_REGISTRY}" >/dev/null
    python -m scripts.day37_aws verify-release --input "$2" --output /tmp/day37-verify-release-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}.json
    ;;
  *) echo 'Usage: day37_tf.sh init|verify-release release.json'; exit 2;;
esac
