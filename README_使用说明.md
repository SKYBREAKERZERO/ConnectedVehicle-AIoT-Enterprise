# Day37 P1 — AWS Staging 企业发布闭环（基于 P0 实现的增量整合版）

## 交付边界

本补丁**未执行 AWS Apply / 发布 / GitHub Push**。它叠加在原 Day37 P0 的 26 文件代码上，覆盖提出的四类问题：Plan→审批→Apply、Foundation 管理、ECS/Terraform 回滚对账、逐 ECS Task 真实 Digest 健康核验。

**严禁直接向 Production 应用此方案**。请先在仓库 feature 分支集成并跑 CI，按 GitHub Environment 的权限与审批规则运行。真正云端通过需要 AWS 账户、OIDC Role、S3 State/Plan Bucket、基础资源、独立审计与完整实测。所有目录内的 AWS ID 都只是格式示例，不代表资源已存在。

## 关键文件

- `.github/workflows/day37-aws-staging.yml`: 11 个 Job，包含 `plan`、`deploy_plan`、`bootstrap`、`deploy`、`verify`、`close`、`recovery`、`gate`。
- `.github/workflows/day37-reconcile.yml`: 手动故障后对账；不执行 Terraform Apply，零漂移前不得解锁。
- `scripts/day37_plan_transport.py`: S3 SSE-KMS 版本化保存私有 Terraform Plan、Run/Attempt/Commit/SHA/VersionId 校验与持久化 S3 发布 Fence。
- `scripts/day37_aws.py`: 用 `list-tasks` + `describe-tasks` 逐任务检查 `containers[].imageDigest` 与 ENI/ALB 健康关联。
- `scripts/day37_gate.py`: Terraform 计划资源类型/操作白名单；部署 Gate 同时要求签名镜像、逐任务运行证据、精确 Plan 和关闭标记的对账证据。
- `infra/terraform/environments/ota-staging-foundation`: 完全**独立 State 与管理员权限**的 Foundation Root。
- `scripts/day37_apply_redis_tls.py`: 经人工审核、显式 `--apply` 后对现有应用设置 TLS Redis 客户端；非自动运行。

## 一、Terraform Plan 与 Apply 必须是两个独立 Job

GitHub `Run workflow` 四种模式不变：`audit`, `plan`, `bootstrap`, `deploy`。

- `plan`: 只进行 Terraform `-refresh-only` 审计 Plan，不 Apply。
- `bootstrap`: `plan` Job 用 `aws-staging-plan` IAM Role 生成二进制 Plan；仅把**脱敏 summary 和 receipt**上传 GitHub Artifact。二进制 Plan 使用 S3 `PutObject --if-none-match '*'`、SSE-KMS、Bucket Versioning，返回不可变 `VersionId`。受保护的 `bootstrap` Job 在审批之后按 VersionId 与 SHA-256 获取并直接 `terraform apply reviewed.tfplan`。
- `deploy`: `publish` 将已验证的 Day36 候选镜像推到 ECR；`deploy_plan` 在独立 Plan Role 下生成 ECS 精确 Digest Plan；审批的 `deploy` Job 只加载并校验 SHA 的同一 S3 Object Version，**不会重新 plan**。Terraform 的 State serial 不一致时 saved-plan Apply 会失败，继续 BLOCKED。
- 审核者需对照 `deploy_plan` Artifact 的摘要及 `GITHUB_STEP_SUMMARY` 中的 Plan SHA-256，核对将批准的 Job 名称里展示的 SHA。**GitHub Environment approval 本身不是密码学上的 Plan SHA 签名**；如果组织要求真正的审签，需要额外的变更管理系统或签名审批收据。
- S3 私有 Plan 可能含敏感数据，**不可上传 GitHub Artifacts 或提交 Git**。Plan Bucket 需要版本控制、Bucket Owner Expected、KMS 权限、S3 Access Logs/CloudTrail、短期生命周期删除，且只允许角色读取自身所需 key/version；应用日志不能输出 Plan 原文。

### 必须新增的 Environment Variables

给 `aws-staging-plan`, `aws-staging-bootstrap`, `aws-staging-publish`, `aws-staging-deploy`, `aws-staging-recovery` 提供（依据 Job 的 env 映射及最小权限，不要把整个权限环境复用）：

- `DAY37_PLAN_BUCKET`: 专用 Staging S3 存储桶，建议与 Terraform State Bucket 分开（同一 AWS Account）；S3 Versioning=Enabled。
- `DAY37_PLAN_PREFIX`: 如 `connected-vehicle/day37-plans/v1`，不可含 `..`。
- `DAY37_PLAN_KMS_ARN`: 本实现要求与 `DAY37_BACKEND_KMS_ARN` **完全相同**，避免未经审核的密钥切换。
- `DAY37_REDIS_AUTH_SECRET_ARN`: 真实 Secrets Manager ARN（有 `AWSCURRENT`）；Terraform 作为 `TF_VAR_redis_auth_secret_arn` 引用。

维持原 P0 的 `DAY37_PLAN_ROLE_ARN`、`DAY37_BOOTSTRAP_ROLE_ARN`、`DAY37_PUBLISH_ROLE_ARN`、`DAY37_DEPLOY_ROLE_ARN`、`DAY37_VERIFY_ROLE_ARN`、`DAY37_RECOVERY_ROLE_ARN`，分别位于不同 Environment。

**最小 IAM 授权需要安全管理员审核后提供**。例如 Plan Role 允许 `s3:GetObject` State、对 `.tflock` 只读/Put/Delete、Plan 指定前缀 `s3:PutObject`（不可覆盖）及只读 Describe；Deploy Role 仅可 Get 指定版本 Plan、写自身 Fence、操作精确 ECS 服务和 Terra State；Publish Role 只能读 Fence 与写指定 ECR Repository/签名；Verify Role 只有 Describe；Recovery Role 可更新精确 ECS Service、只读 Terraform Plan、读取及关闭 Fence。各角色需与 `aws-staging-<mode>` OIDC `sub` 及 Permissions Boundary 对齐。

## 二、独立 Foundation Terraform（由单独管理员运行，不由 Day37 Actions 自动 Apply）

`infra/terraform/environments/ota-staging-foundation/` 定义：

- Staging VPC，跨 2AZ 的 public/private 子网、每 AZ NAT 与路由。
- Internal HTTPS ALB、IP Target Group、`/health/ready` 200 验收、受限入口 CIDR 和 ACM TLS 证书引用。
- RDS PostgreSQL 17 Multi-AZ、at-rest encryption、Managed Master Secret、非公网、备份与 deletion protection。
- Valkey/Redis Multi-AZ、TLS、at-rest encryption、Write-Only `auth_token_wo`（Ephemeral Terraform 输入，不存入 State）。
- Application `app_user` Secret 和 Redis auth Secret 的 **metadata only**（不创建密码值或 DB 用户）。
- RDS/Redis SG 与服务最小网络边界。应用 Root 仅创建两个指定端口（5432、6379）的 ECS SG → 数据库/缓存 SG 入站规则。

**这不是零配置一键部署**。需要管理员实际设置独立 State、ACM 证书、可用 PG17 Minor、受限入口、Redis Token，并批准真实资源和费用。NAT、Multi-AZ RDS、ElastiCache 和 ALB 会产生持续费用。

Foundation 创建后还必须执行独立数据库 Bootstrap（创建 `app_user`、租户 RLS、权限、Schema、业务表、数据）、把 Application Secret 的正确 JSON 写入 `AWSCURRENT`，并把与 `TF_VAR_redis_auth_token` 相同的 Redis 密码版本单独写入 Redis Secret `AWSCURRENT`。**这些值不进入 Terraform State；当前 Terraform 不会替你完成凭据注入。** 先做 Redis TLS 客户端补丁（下一节），否则 ECR/ECS 部署不应执行。

应用 OIDC (`DAY37_APP_OIDC_*`) 采用**真实外部认证服务**，Foundation 不创建 Cognito 或第三方 OIDC；它仍属于需人工核验的外部依赖，不得声称已经完整自动部署。

## 三、Redis TLS 应用兼容（必做）

当前仓库 `enterprise_platform/cache/client.py` 默认使用普通 Redis ConnectionPool。交付提供显式、源代码锚点安全检查的补丁：

```powershell
python -m scripts.day37_apply_redis_tls
python -m scripts.day37_apply_redis_tls --apply
```

它新增 `Settings.redis_tls_enabled`、Python `redis.asyncio.connection.SSLConnection`（强制证书验证），并对 AWS Staging 增加 TLS 与密码 Fail-Closed 校验。ECS Task 将启用 `REDIS_TLS_ENABLED=true`，通过执行角色读取独立 Redis Secret 并注入 `REDIS_PASSWORD`。必须测试实际 Redis TLS 连接与 TLS CA；若企业使用私有 CA，则需额外受控证书分发，不能关闭校验。

## 四、回滚与 Terraform Drift/Fence

- `deploy` 在修改 ECS/State **之前**往 S3 固定键 `DAY37_PLAN_PREFIX/recovery/active.json` 写一次性 `RECONCILIATION_REQUIRED`；任何崩溃/取消会留下 Fence。
- 下一次 `publish` 或 `bootstrap/deploy_plan` 均先读 Fence。存在时 `BLOCKED`，连 ECR 新镜像都不允许推送。
- `recovery` 若旧任务存在则仅恢复之前的 ECS Task Definition，不自动修改数据库结构；不存在旧 Task 时明确失败，要求人工处置；Fence 仍保留。
- 成功新版本的 `verify` 之后，`close` 使用 Recovery 角色核对真实运行任务 Digest、ALB 健康和 `terraform plan -detailed-exitcode` 零漂移。全部通过才能删除 Fence，最终 `gate` 需要 `close` 证据。
- 如果执行了失败回滚或人工修复，先进行管理员批准的 Terraform State/Config 对齐，完成后**单独触发** `day37-reconcile.yml`。必须提供当前 main SHA、旧失败的 Commit/Run/Attempt 和已恢复的带签名 ECR Digest。该 Workflow 独立核对活跃 Fence、ECR 签名、每个运行 Task 和 Terraform 零变更，然后才允许 Recovery Role 清除标记。它自己不运行 `terraform apply` 或数据库降级。

**注意**：Terraform Saved Plan 本身可能含敏感数据，不能作为普通 GitHub Artifact；恢复 Job 只有在 `aws-staging-recovery` Environment 设定独立审核之后才可运行；必须开启 Required Reviewers 和 Prevent Self-review（取决于 GitHub 仓库/计划的支持情况）。

## 五、验证与发布顺序

1. 审核代码，运行 Redis TLS 补丁，更新 IAM 最小权限/S3 Plan Bucket/独立 Foundation 资源配置。
2. 在开发分支运行 `pytest -q tests/unit/test_day37*.py` 与 `terraform fmt/validate`（包括 **两个**根：`ota-staging`、`ota-staging-foundation`，以及 P0 `ota-staging-identity`）。
3. 先由管理员人工 Foundation Plan→Approval→Apply，并配置数据库租户/RLS/Secret/OIDC；否则 Staging 部署门禁应 BLOCKED。
4. Day35/Day36 必须有受保护 main 同 SHA 真实通过证据；Day37 先 `audit`，再 `plan`，然后经审批 `bootstrap`，最后 `deploy`。
5. 真正 AWS 验收需要 `GetCallerIdentity`、RDS/Redis/ALB/API 真实连通性、ECS Task `imageDigest` 和 S3 Fence/零漂移闭环。
6. 不经人工代码审核或正确 IAM 策略，**不得**执行真实 AWS Apply。

## 已知未验证

离线 Pytest/Python/YAML/Shell 检查不等于 Terraform Provider Validate、AWS IaC Plan、GitHub Actions CI、STS 角色验证、真实基础设施或 OTA 端到端。当前仍未执行这些外部验收；不得标记 `AWS_STAGING_SERVICE_VERIFIED`。ZIP 是候选补丁，不会自动推送 GitHub，也不会修改 AWS。
