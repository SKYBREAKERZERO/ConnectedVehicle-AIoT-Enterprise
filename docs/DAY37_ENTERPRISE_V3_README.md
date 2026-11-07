# Day37 Enterprise Staging Release — v3 Overlay

## 本次交付的定位

这是针对仓库 `SKYBREAKERZERO/ConnectedVehicle-AIoT-Enterprise`、分支 `feat/day37-p1-audit-20261107`、基线提交 `b1816954c7242417cd60880c94f182eb6b2357c6` 的**可审核增量源码补丁**。包含完整的修订 Day37 AWS Staging Actions YAML 和独立 Bootstrap Reconciliation YAML；其余原有 `day37_gate.py` / `day37_aws.py` / `day37_plan_transport.py` / Terraform Staging Root 在原仓库中保留和复用。

**不是全量仓库、不是已部署 AWS Staging、不是 Production Release、不是 AWS L4/L5 验收通过证明。** 没有为用户执行 AWS Apply、IAM 变更、GitHub push/merge 或远程审批。任何真实运行前必须审核代码、GitHub Environment/IAM 和 S3 Bucket Policy。

## 已实现内容

1. **审批与准入**：从 GitHub Environment 审批 API 核对独立审核人与包含精确 `commit/run_id/run_attempt/aws_account_id/plan_sha256/policy_sha256/environment/phase` 的审批评论；获取 AWS OIDC 前校验，Final Gate 复核。
2. **S3 Durable Fence**：Bootstrap/Deploy 同步采用版本化 SSE-KMS 对象、`IfNoneMatch` / `IfMatch` 比较交换；ACTIVE 不允许下一次发布；仅独立 Recovery Role 可生成 CLOSED 证明；保留旧 Fence 状态迁移阻断。
3. **Bootstrap 失败对账**：Bootstrap Apply Role **无权自行关闭**；新增独立 `bootstrap_close` Job 读取 AWS 状态和 Terraform No-Op，另有人工 Bootstrap Recovery 工作流处理部分 Apply。
4. **Recovery**：实时从 S3 读 ACTIVE Fence，Checkpoint 不存在则不自动回滚；原始 `Checkpoint` 哈希必须匹配 S3，恢复前检查 ECS Task Definition 与失败镜像 Digest，禁止覆盖后来的部署。回滚完成仍保持 Fence ACTIVE。
5. **证据闭环**：发布、Plan/Policy、Commit/Attempt/Account、S3 CLOSED 回执与 Proof 哈希绑定；Final Gate 要求 12 Job 完整 DAG 的正确 Success/Skipped 组合。
6. **IaC 安全扫描修复脚本**：增加 RDS `rds.force_ssl=1` 参数和两个真实 Secrets Manager Secret Rotation 资源，**没有跳过 Checkov**；Lambda 和凭据轮换实际能力必须由独立管理员先部署和演练。
7. **旧测试升级**：以精确文本锚点更新 3 个仓库已有 Day37 合同测试（不是删除或跳过）。

详细技术与运维说明见 `docs/DAY37_ENTERPRISE_RUNBOOK.md` 和 `docs/CKV_REMEDIATION.md`。

## 集成方法（Windows PowerShell，本地，无云修改）

首先在已有真实仓库中检出已审查分支并确保工作区清洁：

```powershell
cd D:\project\ConnectedVehicle-AIoT-Enterprise
git fetch origin
git switch feat/day37-p1-audit-20261107
git rev-parse HEAD
# 必须为 b1816954c7242417cd60880c94f182eb6b2357c6
git status -sb
```

解压 ZIP 取得 `day37_enterprise_v3` 目录，在其内部运行工具：

```powershell
python .\day37_enterprise_v3\tools\apply_enterprise_overlay.py --repo . --preview-dir .day37\enterprise-preview
# 逐文件审查 .day37\enterprise-preview 的 37 个生成内容
python .\day37_enterprise_v3\tools\apply_enterprise_overlay.py --repo . --apply
```

安装器检查 HEAD、必要原始文件及关键文件是否脏；只改本地工作区，不调用 AWS / Terraform / GitHub API。如原仓库 SHA 已改变，**不要直接修改 `--expect-sha` 绕过审核**；需先重新审查 diff 和接口契约。

再运行完整仓库测试：

```powershell
python -m pytest tests/unit -q
python -m pytest tests/unit/test_day37_workflow.py tests/unit/test_day37_p1_workflow.py tests/unit/test_day37_manual_reconcile.py -q
ruff check scripts/day37_* tests/unit/test_day37_*
mypy scripts/day37_approval.py scripts/day37_fence.py scripts/day37_reconcile.py
terraform -chdir=infra/terraform/environments/ota-staging fmt -check -recursive
terraform -chdir=infra/terraform/environments/ota-staging init -backend=false -input=false
terraform -chdir=infra/terraform/environments/ota-staging validate
```

**注意**：本地运行 `ruff/mypy` 可能因新增代码的格式/类型问题失败；不能把当前离线 pytest 结果冒充仓库 Python 3.12 质量门禁通过。独立 Foundation Root 应另外先运行 `terraform fmt`、`terraform validate`、真实 Checkov 后再审核。

## 风险及未完成项目（保持 BLOCKED）

- **GitHub**：本 Overlay 未推送到 Feature Branch、未合并至 Protected Main；该 SHA 的 IaC `Run 42339813267` 存在已知 Checkov 失败。
- **AWS**：没有运行 S3 并发 CAS、ECS Task/ALB、KMS、IAM 分离、Terraform Apply/Drift 或 CloudTrail 验收。
- **Rotation**：两个经审核且可工作的 Lambda 与 Redis AUTH/数据库 RLS 用户切换协议尚未提供，严禁在此之前执行 Foundation Apply。`rotate_immediately=false` 不意味着跳过测试。
- **S3 信任边界**：对抗被攻陷的 Apply IAM Principal，需要更强的受控 Fence Broker：仅依赖 S3 IAM 条件 PUT 无法证明 JSON 状态机未被越权写入。此部分尚未实现完整防恶意权限模型。
- **审批 API**：需要实际配置 GitHub Environment required reviewers、禁止自审、正确评论格式，并运行真实的 Approval API 验证。
- **Production**：Day37 严格限 Staging，所有证据 `production_authorized=false`，并不包含生产发布权或真实车辆 ECU 安全验收。

只有全部真实 CI + Cloud 检查通过，才能宣布 Day37 AWS Staging READY；否则 `BLOCKED`。
