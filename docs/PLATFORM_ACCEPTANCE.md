# 平台缺口与验收证据

这份记录区分代码／本地验证、GitHub 验收和真实 AWS 运行证据。工作区测试通过不代表最新 GitHub 提交成功，也不代表 AWS 部署、故障转移或灾备已完成。

| 优先级 | 项目 | 当前交付 | 仍需验收 |
|---|---|---|---|
| P0 | IaC Gate | 本地完整 Gate：19 次 Terraform 契约测试、安全扫描、禁止删除／替换、隔离 LocalStack apply、第二次 plan 无变更 | 修改提交后两条 GitHub Gate 必须在同一 SHA 成功 |
| P0 | main 强制保护 | protect_main 同时要求 IaC quality gate 和 Runtime quality gate，限定 GitHub Actions app 15368；已实际配置 main 并通过只读 --verify 读回验证 | 后续每次合并必须两条 Gate 同时成功并取得合格 review |
| P1 | 车辆 ACK／执行结果 | 签名设备身份、车辆 ID 绑定、状态推进、幂等回报账本、失败码；管理员超时对账 | 真实设备身份发放和车辆固件回报集成 |
| P1 | 真实 AWS | 新增只读配置验收脚本，检查数据库／缓存加密与 HA、三个 ECS 服务、Secret IAM 隔离、队列／DLQ、告警 | Dev Terraform 仍是 scaffold；当前 AWS User_test 可读取账号，但 EC2／ECS／RDS／Secrets Manager 查询均被 IAM 拒绝。需部署／验收身份、VPC／子网、域名／证书、镜像与 IdP，完成实际部署和状态驱动 plan Gate |
| P1 | Contract Gate | AST 模块边界、HTTP／事件／MQTT／设备 Schema 快照、基线兼容检查，纳入 Runtime Gate；全仓库 mypy | 首次引入快照没有历史快照可比较；后续 PR 自动对比基线 |
| P1 | DLQ／Outbox 运维 | owner 专用对账、原始事件校验、审计重放、受限整队列 redrive、模糊结果拒绝自动重试 | AWS redrive 实际验收与值班演练；当前 SDK 路径为真实 PostgreSQL＋受控 SDK 故障测试 |
| P1 | 身份体系 | RS256 固定 issuer／audience／JWKS，Cognito access-token 校验；生产禁用静态服务 Token | IdP 用户／设备生命周期、MFA、授权流程、租户与车辆可信 claims 发放 |
| P2 | Telemetry | 设备身份校验、数据范围和时效校验、幂等入库、租户查询、相同时间戳的游标分页 | 真车遥测上报；保留、分区和规模容量设计 |
| P2 | 可观测性 | 保护的 Prometheus scrape、受限标签、OTLP 导出与停机 flush、Collector 示例、API 告警规则 | Collector／Prometheus／告警通知目标部署与真实触发验证；worker 业务指标部署仍需补全 |
| P2 | HA／性能／灾备 | 三进程故障恢复测试；20 次并发同幂等键请求；pg_dump＋新数据库 pg_restore 后核对业务记录 | 真实 AWS 多 AZ 故障转移、真实容量曲线、RPO／RTO 与跨区域恢复证明 |

## 车辆回报和遥测

命令 API 的 HTTP 202 表示持久化接受。MQTT QoS 1 PUBACK 后为 `sent`；车辆回报 `acknowledged` 才代表车辆收到，`succeeded`／`failed` 才代表执行结果。

- `POST /vehicles/{vehicle_id}/commands/{command_id}/reports`：`event_id`、`status`（acknowledged／succeeded／failed）、带时区 `occurred_at`；失败必须携带安全的 `failure_code`。
- `GET /vehicles/{vehicle_id}/commands/{command_id}`：需 `vehicle:read`，按已验证身份的租户查询。
- `POST /vehicles/{vehicle_id}/telemetry`：`event_id`、带时区 `measured_at`、`speed_kph`、`battery_percent`、`temperature_c`。时间窗口为过去一天至未来五分钟。
- `GET /vehicles/{vehicle_id}/telemetry?limit=50`：需 `telemetry:read`，最大 100。下一页同时传最后一条的 `before=measured_at` 与 `before_event_id=event_id`，避免同时间戳样本遗漏。

设备只获得 `command:report`／`telemetry:publish`，签名 `vehicle_id` 必须匹配 URL，签名租户必须匹配持久化车辆／命令。事件 ID 重用为不同内容返回 409；相同内容重试成功。事务 advisory lock 与命令行锁串行化并发回报；延迟 ACK 不回退终态。相互矛盾的执行终态返回 409。

`command_reports` 和 `telemetry_samples` 是追加记录；app_user 只增加这两表的 SELECT／INSERT，以及 remote_commands.status／updated_at 的 UPDATE。两种 worker 的权限保持隔离。operator_actions 仅管理身份访问。Alembic／GRANT 仍由独立 owner 凭据执行，部署时先迁移再重新 provision GRANT，最后滚动更新运行时。

## OIDC 与 Cognito

配置 `.env.example` 中固定 issuer／audience／JWKS；不得从 token 的 jku／x5u 选择信任源。签名算法固定 RS256，验证 exp／iat／iss／sub，拒绝 ID token。JWKS 缓存五分钟，新 kid 触发重新获取；认证并发查询限制为四个，单次查询超时受配置约束。

租户、principal_type、vehicle_id 和权限 scope 必须由可信 IdP 发放，用户不得自行修改。设备权限会被裁剪，不能通过额外 scope 获得命令下发／其他车辆读取权限。静态 PEM 仅 local／test 使用。生产静态 API_SERVICE_TOKEN 被配置校验拒绝。

Cognito 设 `OIDC_TOKEN_PROFILE=cognito`，audience 是 app client ID，校验 access token 的 client_id 与 token_use。资源服务器 scope 若为 `vehicle-api/vehicle:read`，设 `OIDC_SCOPE_PREFIX=vehicle-api/`。租户／设备 claims 需要可信 pre-token-generation 配置；不要假定 Cognito 默认 access token 含自定义租户属性。用户登录、MFA、注销与设备注册交给 IdP，当前应用交付的是验证／授权入口。

参考：[Cognito token 验证](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html)。

## 运维操作

所有操作需要显式 MIGRATION_DATABASE_USERNAME／PASSWORD，拒绝三个 runtime user。默认 dry-run；不能把管理凭据放到 worker 环境。

```powershell
.\.venv\Scripts\python.exe -m database.operations reconcile
.\.venv\Scripts\python.exe -m database.operations outbox-replay --id <outbox-uuid> --operation-id <new-uuid> --actor <operator-id> --reason <incident-reference> --expected-attempts 10
# 审阅 dry-run 后，同一参数追加 --apply
.\.venv\Scripts\python.exe -m database.operations command-timeouts --actor <operator-id> --reason <incident-reference>
# 审阅过期命令后追加 --apply；每批最多 100，终态不再重复更新
```

Outbox 重放仅允许 FAILED、预期尝试次数、有效契约和原始 command／tenant／vehicle／类型／时间匹配、未发送且未过期的命令。重放不修改事件 ID／payload，不清除 Redis 去重，不重置已成功命令。审计写入与恢复 pending 在同一事务中完成。过期或已执行命令需要业务授权后发新命令。

```powershell
.\.venv\Scripts\python.exe -m database.operations dlq-redrive --source-url <dlq-url> --destination-url <original-queue-url> --operation-id <new-uuid> --actor <operator-id> --reason <incident-reference> --rate 1
# 逐一核对 poison 消息、命令到期状态与源故障已修复，确认整队列重放后追加 --allow-bulk --apply
.\.venv\Scripts\python.exe -m database.operations dlq-status --operation-id <same-uuid>
```

目的队列必须是配置该 DLQ 的原始队列，速率限制 1–10 条／秒。调用前先持久化 intent，再启动 AWS managed redrive。客户端 SDK 自动重试关闭；超时／进程崩溃后 intent 不自动重试，需核对 ListMessageMoveTasks、队列状态、CloudTrail 和审计记录。status 不把未知任务认定成功。Managed redrive 是整队列操作，不能用来选择性修复 poison payload；不能确认全部消息时停止整队列重放，走人工隔离／业务重新下发流程。

参考：[SQS managed redrive API](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_StartMessageMoveTask.html)。

## CI 和质量命令

```powershell
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\ruff.exe format --check .
.\.venv\Scripts\mypy.exe .
.\.venv\Scripts\python.exe -m scripts.contracts
.\.venv\Scripts\pytest.exe tests/unit tests/contract tests/e2e/test_independent_runtimes.py tests/integration/security/test_database_runtime_permissions.py -q
.\.venv-iac\Scripts\python.exe -m scripts.iac.gate --baseline <baseline-checkout>
.\.venv\Scripts\python.exe -m scripts.iac.protect_main --repo SKYBREAKERZERO/ConnectedVehicle-AIoT-Enterprise
# 管理员审阅 JSON 后追加 --apply，再独立执行 --verify
```

Runtime Gate 运行全仓库 ruff／mypy 与真实依赖测试；契约快照与运行时模型必须一致，既有版本不能移除／改变类型、枚举、约束或增加必填字段。新增可选字段允许；破坏性协议需新版本并保留旧消费者。Pydantic 与质量工具固定为已验证版本，升级需审阅 Schema 差异。

保护验证要求两条 check 同时绑定 Actions app 15368、分支 up-to-date、admin enforcement、Code Owner／stale review／最后一次 push 审批、至少一个 review、会话解决以及禁止 force push／delete。管理员和具备资格的 reviewer 是平台外部前提。

## 观测、AWS 与灾备证据

`/metrics` 默认 403，显式随机 METRICS_TOKEN 至少 32 字符。Collector 使用独立 scrape 身份；指标标签只含 HTTP method、路由模板、状态码，不含车辆／租户／原始路径。`infra/observability/alerts.yml` 包含不可用、5xx 比例和 p95 延迟告警；Collector 示例只绑定 loopback，远端导出使用 HTTPS。这里只交付配置，部署与告警接收尚待验收。

`python -m scripts.aws_acceptance --target <owned-target.json> --report <report.json>` 只读检查显式账号及资源，不创建／修改 AWS，不读取 Secret value；输出仅验收结果。target 字段为 account、region、database_id、cache_id、cluster、services（api/outbox/remote-command）、queue_url、dlq_url、secrets（三种 runtime Secret ID）、roles（三种 IAM role ARN）、alarm_names。成功仅证明所列配置检查通过，不能证明车辆链路、负载能力或故障转移；这些需另外运行真实 AWS 演练。

E2E 生成临时 `resilience-evidence.json`，记录 20 次并发同幂等键请求耗时和新数据库恢复核对耗时；不会当作生产 p95／吞吐量／RPO／RTO。CI 的 Docker 本地恢复也不能证明多 AZ 切换或跨区域灾备。真实验收应记录部署 SHA／镜像 digest、故障时间、恢复时间、丢失／重复命令与遥测数、备份时间、恢复点及目标阈值。
