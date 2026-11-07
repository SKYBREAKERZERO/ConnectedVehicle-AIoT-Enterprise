# IaC P0 — CKV2_AWS_57 / CKV2_AWS_69 修复契约

GitHub 实际 `IaC quality gates` Run `42339813267` 的 security phase 报告：

- `CKV2_AWS_57`: `aws_secretsmanager_secret.application`, `aws_secretsmanager_secret.redis_auth`
- `CKV2_AWS_69`: `aws_db_instance.postgres`

`tools/patch_foundation.py` 是针对 `infra/terraform/environments/ota-staging-foundation/main.tf` 已审查版本的**有条件、拒绝不明输入**补丁。它修正 RDS Parameter Group 的 `rds.force_ssl = 1`，并加入两项真实 `aws_secretsmanager_secret_rotation`，没有使用 Checkov suppress/skip。

**重要先决条件**：

1. `application_rotation_lambda_arn` 必须指向已经由独立管理员审查并部署的真实 Lambda，能安全执行 `createSecret`、`setSecret`、`testSecret`、`finishSecret`，且校验 `app_user` 租户 RLS、安全连接及下游的凭据刷新。
2. `redis_rotation_lambda_arn` 必须使用与实际 ElastiCache AUTH 的双令牌/分阶段更新一致的策略；如果只是更新 Secrets Manager 的 AWSCURRENT 而未同步 Redis，可能导致连接服务中断。
3. 两个 Secret 已有 AWSCURRENT 版本、Lambda 的资源策略授予 Secrets Manager 调用权限、KMS 解密权限已最小化配置；Lambda 处于正确 VPC/子网。
4. `rotate_immediately = false` 仍可能触发 `testSecret` 检查，不是“可以不部署 Lambda”的绕过。**不满足条件不要执行 Terraform Apply。**
5. 独立 Foundation Root（RDS / Redis / VPC）只能由专用管理员审批和部署，绝不可由 Day37 发布者执行。修复已存在的生产性资源仍需关注 RDS TLS 参数是否触发连接中断/重启。
6. 实际运行 `terraform fmt -check`, `terraform init -backend=false`, `terraform validate`, 固定版本 Checkov 再进行批准；当前交付只保证补丁文本和本地契约测试。

示例（本地预览，不 Apply）：

```powershell
python tools/patch_foundation.py --repo . --output .day37/preview/foundation.tf
# 审查差异，确认 Lambda 真实可用后：
python tools/patch_foundation.py --repo . --apply
```

为避免 Checkov 假阳性/错误通过，请在**最终 Terraform Plan** 里确认 rotation 资源确实将被创建，Secret 已存在 AWSCURRENT，且独立 Lambda 安全测试通过；仅有 HCL 关系并不能证明运行态轮换。
