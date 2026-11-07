# Day37 AWS Staging · 企业级发布、失败恢复及审核 Runbook

## 已修改的执行边界

基线：`SKYBREAKERZERO/ConnectedVehicle-AIoT-Enterprise`、Feature Branch `feat/day37-p1-audit-20261107`、HEAD `b1816954c7242417cd60880c94f182eb6b2357c6`。本 ZIP 是**待集成 Overlay**，不是已经通过 AWS 的全量仓库或远程提交。

- `source`: 无 AWS OIDC；检查全套旧 Day37 测试 + 新 Fence/Approval/Recovery/Workflow 单测。
- `admission`: Protected Main、精确 Commit、Day35/Day36 同次证据。
- `plan`: Refresh-only 审查；Bootstrap Plan 通过保守策略后保存在私有版本化 S3，产生 `plan_sha256` 和 `policy_sha256`。
- `bootstrap`: 审核 GitHub Environment 审批历史 **与同一次 Plan JSON 评论** → STS Bootstrap Role → 精确 Saved Plan → ACTIVE Fence → Apply → AWS 基础设施核验。**不得自行关闭 Fence**。
- `bootstrap_close`: 独立 Recovery Role，检查真实 AWS + Terraform No-Op + S3 CAS 关闭 → Artifact `closed-fence.json` + `proof.json`。
- `publish` + `deploy_plan`: ECR Immutable Digest/Cosign + 同镜像 Saved Plan。
- `deploy`: 同次 GitHub 审批绑定后 STS Deploy Role → 健康旧 Task Definition Checkpoint → ACTIVE Fence → 精确 Terraform Apply。
- `verify` + `close`: 实际 ECS RUNNING Tasks 镜像 Digest + ALB Targets；独立 Terraform Zero Drift；Recovery Role 关闭 ACTIVE Fence。
- `recovery`: 从 S3 **实时探测** ACTIVE Fence；Checkpoint 丢失或锁不匹配时只 BLOCK、不可回滚；确认全部身份后才恢复旧 ECS Task Definition，**不清理 Fence**。
- `gate`: 12 Job 完整状态、版本/哈希/计划/运行证据、CLOSED 回执和真实 GitHub 审批历史；任一必要依赖失败/跳过/取消，`BLOCKED` 非零退出。

## 人工审查 Saved Plan（必须）

`plan`/`deploy_plan` 成功后，Job Summary 中的 `approval-claim.json` 是下游审查人的**精确审批文本**，包含 `phase`、`environment`、`plan_sha256`、`policy_sha256`、`commit`、`run_id`、`run_attempt`、`aws_account_id`。审核人须独立检查 sanitized Plan summary、变更差异、目标环境及运维变更单，把**完整未修改的 JSON** 作为 GitHub Environment 的 approval comment。Reviewer 不能是触发运行的 `GITHUB_ACTOR`。`day37_approval.py` 再从 GitHub Workflow Run Review History API 读取审批，并验证确切身份/评论/Plan 时间窗口；独立 Final Gate 重新检查。仅显示 SHA 的 Job 名称不足以证明审批。

`GitHub Environment` 必须真实开启 required reviewers、分支限制及 prevent self-review。若审批已通过但 comment 缺失或不匹配，**必须重新发起受审查的运行**，不能跳过校验。

## 独立恢复

- **Bootstrap 部分 Apply**：无自动删除/回滚基础设施。修复必须由独立管理员审查 Terraform State/实际资源后完成。管理员手动执行 `day37-bootstrap-reconcile.yml`，填写失败的 Commit/Run/Attempt 和当前 Protected Main HEAD；独立 Recovery Role 做 `bootstrap-verify` + No-Op Terraform，才能 CAS 关闭原 Bootstrap Fence。
- **Deploy 部分 Apply**：Checkpoint 正确且 Live S3 Fence 与失败发布完全一致，才自动恢复旧 ECS Task Definition；即使 ECS 恢复成功仍要求人工对账，不能自动关闭 Fence。
- **Deploy 人工对账**：使用原有 `.github/workflows/day37-reconcile.yml` 经补丁修订版本，检查 Cosign、ECR Manifest、真实 ECS Task/ALB、Terraform No-Op，然后 `manual-close --phase deploy`。它永远不能关闭 Bootstrap Fence。
- Runner 取消、网络分区、S3 AccessDenied、Checkpoint 不存在、Plan 版本不一致、Approval 失效、Terraform 退出码非 0：均视为未知状态并保留 ACTIVE Fence。

## IAM/S3 持久化控制（需独立管理员实施）

- S3 Versioning Enabled、KMS CMK 同 Account/Region；强制 SSE-KMS、CloudTrail Data Events，记录 `PutObject` 及授权决策。
- `.../recovery/active-v2.json` 必须拒绝任何 `DeleteObject` / `DeleteObjectVersion`；强制 `s3:if-match` 或 `s3:if-none-match` 条件 PUT。并发只允许一个 CAS 成功。
- Bootstrap/Deploy Role 只获严格的 Mark 所需权限；Recovery Role 可读写 CLOSED 转换。**单凭 S3 IAM 无法验证 JSON 的 `state` 字段或审批是否真实**，仍需代码、工作流职责隔离及可审计审批。对抗恶意/被攻破的 Apply Role，应增加由独立身份控制的 Fence Broker，而非让 Apply Role 自由 PutObject。本包未声称实现了该信任边界。
- Six-Roles OIDC identity 仍按现有 `ota-staging-identity` Root，不能将宽权限放入同一个 Application Secret/Worker。
- `production_authorized=false` / `release_authorized=false` 是 Day37 所有决策的强制条件，不能与物理 ECU OTA 回滚证明混淆。

## 基础设施安全扫描修复

- `CKV2_AWS_69`: PostgreSQL 17 Parameter Group `rds.force_ssl=1`，核实实际 RDS 参数生效和客户端证书链。
- `CKV2_AWS_57`: 加入实际 Secrets Manager Rotation Resource，**要求已有两个真实独立 Lambda ARN，且已测试 AWSCURRENT / Redis Token 协议**；`rotate_immediately=false` 仍可能触发 `testSecret`。不能用假 ARN/无效 Rotation/Checkov skip 假装绿灯。
- 两项修改都属于 **独立 Foundation Root** 管理，严禁在 Day37 Bootstrap/Deploy 自动 Apply。

## CI/验收要求

本地：

```powershell
python -m pytest tests/unit/test_day37_* -q
python -m compileall -q scripts
terraform -chdir=infra/terraform/environments/ota-staging fmt -check
terraform -chdir=infra/terraform/environments/ota-staging init -backend=false -input=false
terraform -chdir=infra/terraform/environments/ota-staging validate
```

分环境测试：保存真实 GitHub Actions Job/Attempt、完整 IaC Security Scan 和 Python 3.12/Ruff/Mypy 结果。真实 AWS 必须执行并保存：

1. S3 CAS 并发 2 个 Runner，只有 1 个拿锁；已关闭 Fence 重放拒绝。
2. Bootstrap 部分 Apply + 强制崩溃后仍 ACTIVE；缺少实际资源时 Zero Drift=2，无法关闭；维修后独立手动复核。
3. Deploy Checkpoint/Plan/Policy/Account/Run/Attempt 篡改全部拒绝。
4. Runner 在 ACTIVE S3 写入成功但 Artifact 上传前崩溃，Recovery 以 **S3** 为准，不依赖 Fence Artifact。
5. ECS 真正运行的镜像 Digest、Task Definition、ENI IP 和 ALB target 健康全部核验。
6. 未认证审批/评论不匹配/自我审批全部 BLOCK；独立 reviewer 精确批准同 SHA 才允许临时 AWS 凭据。
7. Terraform `plan -detailed-exitcode`=0、S3 Fence CLOSED Version ID 与 proof SHA256 完整绑定；Final Gate 再查询 GitHub Approvals。
8. 真实 PostgreSQL SSL/TLS、Secrets Manager 轮换（Redis Token 与 RLS DB 的安全切换）经审查通过；IaC 门禁全绿。

**没有完成真实 AWS/CI 的，最终结果固定 `BLOCKED`。** 禁止声称 Day37 已达到 L4/L5 生产认证。
