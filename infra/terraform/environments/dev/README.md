# Real AWS Dev foundation validation

The LocalStack IaC CI gate now validates the AWS Dev root **offline** and scans it
with Checkov. It does not contact AWS, provision remote state or execute real
AWS plans. Run a separate real AWS plan only with explicit operator approval.

## Safe operator procedure (real AWS; never in LocalStack CI)

1. Obtain a short-lived SSO/role session; do not commit AWS credentials.
2. Set `AWS_PROFILE` to an approved identity and set `AWS_ACCOUNT_ID` from an
   independently approved account inventory. Verify it matches
   `aws sts get-caller-identity`.
3. Obtain a pre-existing, versioned, encrypted, private S3 Terraform state bucket
   in the intended account. Ensure bucket access and S3 lockfile permissions.
4. Review VPC CIDRs and recurring *interface endpoint* costs in the region.
5. From `infra/terraform/environments/dev`, use:

```powershell
$env:AWS_PROFILE = "your-approved-sso-profile"
$Account = "YOUR_12_DIGIT_ACCOUNT_ID"
$Region = "ap-northeast-1"
$Actual = aws sts get-caller-identity --query Account --output text
if ($LASTEXITCODE -ne 0 -or $Actual -ne $Account) { throw "AWS account mismatch" }

terraform fmt -check -recursive
terraform init -reconfigure -input=false `
  -backend-config="bucket=YOUR_EXISTING_VERSIONED_STATE_BUCKET" `
  -backend-config="key=connected-vehicle/dev/terraform.tfstate" `
  -backend-config="region=$Region" `
  -backend-config="use_lockfile=true"
if ($LASTEXITCODE -ne 0) { throw "backend init failed" }

terraform validate
if ($LASTEXITCODE -ne 0) { throw "validate failed" }
terraform plan -input=false -detailed-exitcode -var="aws_account_id=$Account" -out=aws-dev.tfplan
if ($LASTEXITCODE -notin @(0,2)) { throw "plan failed" }
terraform show -json aws-dev.tfplan > aws-dev-plan.json
if ($LASTEXITCODE -ne 0) { throw "plan export failed" }
python -m scripts.iac.aws_dev_plan_policy aws-dev-plan.json
if ($LASTEXITCODE -ne 0) { throw "AWS plan policy failed" }
```

Run the Python module from repository root, or set PYTHONPATH to that root.
**Do not upload** binary plan or full plan JSON: sensitive configuration may be
present. Do not run `terraform apply` as part of this process.

## Gate status

- Offline format/validate/Checkov are CI responsibilities.
- Identity match, state backend and live plan are operator responsibilities.
- Plan evaluation rejects deletes/replacements and any unapproved resource
  kinds; any unknown or deferred values block PASS.
