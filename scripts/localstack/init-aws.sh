#!/bin/sh
set -eu

AWS_REGION="${AWS_DEFAULT_REGION:-ap-northeast-1}"
MAIN_QUEUE="${VEHICLE_COMMAND_QUEUE_NAME:-connected-vehicle-command}"
DLQ_QUEUE="${MAIN_QUEUE}-dlq"

echo "[localstack-init] provisioning SQS resources"

DLQ_URL="$(
    awslocal sqs get-queue-url \
        --queue-name "$DLQ_QUEUE" \
        --region "$AWS_REGION" \
        --query 'QueueUrl' \
        --output text \
        2>/dev/null ||
    awslocal sqs create-queue \
        --queue-name "$DLQ_QUEUE" \
        --region "$AWS_REGION" \
        --query 'QueueUrl' \
        --output text
)"

awslocal sqs set-queue-attributes \
    --queue-url "$DLQ_URL" \
    --region "$AWS_REGION" \
    --attributes '{"MessageRetentionPeriod":"1209600"}'

DLQ_ARN="$(
    awslocal sqs get-queue-attributes \
        --queue-url "$DLQ_URL" \
        --region "$AWS_REGION" \
        --attribute-names QueueArn \
        --query 'Attributes.QueueArn' \
        --output text
)"

MAIN_URL="$(
    awslocal sqs get-queue-url \
        --queue-name "$MAIN_QUEUE" \
        --region "$AWS_REGION" \
        --query 'QueueUrl' \
        --output text \
        2>/dev/null ||
    awslocal sqs create-queue \
        --queue-name "$MAIN_QUEUE" \
        --region "$AWS_REGION" \
        --query 'QueueUrl' \
        --output text
)"

awslocal sqs set-queue-attributes \
    --queue-url "$MAIN_URL" \
    --region "$AWS_REGION" \
    --attributes \
        '{"VisibilityTimeout":"60","ReceiveMessageWaitTimeSeconds":"20","MessageRetentionPeriod":"345600"}'

REDRIVE_ATTRIBUTES="$(
    printf \
        '{"RedrivePolicy":"{\"deadLetterTargetArn\":\"%s\",\"maxReceiveCount\":\"5\"}"}' \
        "$DLQ_ARN"
)"

awslocal sqs set-queue-attributes \
    --queue-url "$MAIN_URL" \
    --region "$AWS_REGION" \
    --attributes "$REDRIVE_ATTRIBUTES"

echo "[localstack-init] main queue: $MAIN_QUEUE"
echo "[localstack-init] dlq: $DLQ_QUEUE"
echo "[localstack-init] provisioning complete"