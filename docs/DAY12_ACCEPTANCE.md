# Day12 本地安全、恢复与发布验收

范围限定为本地 PostgreSQL、SQLite、免费 LocalStack 镜像、Prometheus 和 Alertmanager。
不部署真实 AWS，不调用付费云资源。本文件定义验收口径；实际结果以对应提交的
Runtime/IaC 检查和 `day12-local-acceptance` 产物为准。

| 阶段 | 实现与验收 | 证据文件 |
| --- | --- | --- |
| 12A | Day11 发布提交备份、五表多租户历史数据、非超级用户迁移、Schema/权限一致性、失败回滚重试、大表并发、两个迁移进程互斥及共享连接超时。固定租户身份和跨租户拒绝继续验证。 | day12-12a-migrations.json、day12-12a-rls.json、day12-migration-failure-retry.json、day12-migration-scale-locks.json、day12-migration-guards.json |
| 12B | 六角色 × 六 Secret 配置矩阵；实际 PostgreSQL 与 LocalStack 凭据发布、部分发布失败补偿、补偿失败后显式恢复和安全重试。KMS 上下文与绑定验证。 | day12-12b-identity-matrix.json、day12-credential-rotation.json |
| 12C | 从真实 SQLite/PostgreSQL 收集指标，五类告警分别观察 Prometheus FIRING、Webhook firing、恢复后的 Webhook resolved，并关联同一次告警。 | day12-12c-alert-lifecycle.json |
| 12D | 备份 SHA256、完整性校验、恢复前摘要比对、设备归属、命令去重、ACK 前置顺序、事件重放审计和恢复操作审计；审计失败时恢复文件不发布。 | day12-12d-restore.json |
| 12E | Ruff、格式、mypy、pytest、迁移、Terraform 验证、安全扫描、模块测试和计划策略全部通过；两条必需 CI 通过后合并 PR，再核对 main。 | day12-acceptance.json、iac-gate-summary、GitHub 检查 |
| Day14 补充 | 缺失 Secret 拒绝；v2 日志配置绑定；非法目标、版本及重复恢复的无副作用检查。 | day12-credential-recovery-hardening.json |

Day14 的格式兼容、操作范围与详细断言见 [DAY14_CREDENTIAL_RECOVERY.md](DAY14_CREDENTIAL_RECOVERY.md)。

所有运行证据、私有备份、SQLite 文件和 Terraform state 放在被 Git 忽略的目录。
CI 上传的 JSON 不包含数据库密码、Token、SecretString 或 Terraform state。
`scripts.day12_evidence` 要求全部阶段记录存在，验证告警实例和结果，再生成文件摘要清单；
缺失任何记录会使 Runtime Gate 失败。
所有阶段记录携带版本、完整 Commit SHA 和本次批次 ID，旧提交或混合批次不能重新标记为通过。
CI 批次 ID 使用 workflow run ID 与 attempt；本地每次验收设置新的 ID，并使用独立输出目录。
验收器重新计算 Catalog 摘要及差异、检查 Revision/角色属性/数据关联/租户计数，
逐项核对 Secret 矩阵坐标和六类 KMS 上下文探针，拒绝重复坐标或仅维持相同允许数量的错配。

## 12A：迁移与租户隔离

历史 e15c849a320b/f26d950b431c 迁移使用对应版本的 SQL 快照。
新增 b48f720da63e 同样读取固定快照，后续修改运行时 provisioning SQL 不会改变旧迁移。
新库由独立非超级用户 `migration_owner` 从空库升级。旧库来自 Day11 发布提交
`819061de39eb2adb0ce47b61d465cd0f7891a3c1` 的独立 Git archive：使用发布代码升级到其 head，
填充两租户的六辆车、18 条命令、36 条关联回报、12 条遥测和 18 条 Outbox 事件，
生成真实 PostgreSQL custom-format pg_dump，再校验 SHA256 并恢复到另一数据库升级。
这份 CI 备份是发布代码生成的合成业务样本，不宣称包含真实生产历史数据。

五表逐行完整记录及 Payload 通过规范化 JSON SHA256 比较，同时核对租户分布、
车辆/命令/报告/Outbox 归属关联和序列状态。Catalog 快照比较列、索引、约束、RLS、
角色属性、成员关系、表/列/函数/Schema/数据库 GRANT、默认权限和 Owner。
pg_restore 会把 varchar 枚举数组转换成等价的逐元素 text cast；只归一化该表示差异，
原始 CHECK 定义仍保留。负向测试证明增加 OR true、改变列或枚举值不会被归一化掩盖。
升级后的完整 Catalog 必须与全新数据库一致，重复升级必须保持全部快照不变。

集群管理员只负责初始建库、建角色与密码管理；表、列、函数和默认权限由 Schema Owner 配置。
实际新旧 Schema 升级由数据库所有者
`migration_owner` 执行，角色明确 NOSUPERUSER、NOBYPASSRLS、NOCREATEDB、NOCREATEROLE、
NOREPLICATION、NOINHERIT，且无角色成员关系。CI 的容器管理员为 `cluster_bootstrap`；
其凭据只注入 bootstrap 步骤，Alembic 使用独立 `migration_owner`。
共享连接与 CLI 均检查实际 session_user/current_user、数据库 Owner 和角色属性；
超级用户、SET ROLE 代理、成员关系和危险属性漂移在执行 DDL 前拒绝。
具体部署与恢复流程见 [DATABASE_MANAGEMENT.md](DATABASE_MANAGEMENT.md)。

SQL 故障注入发生在绑定表/函数创建和车辆策略变更之后；服务端返回 22012，
事务必须同时回滚 Revision、DDL、Policy、权限与历史数据，随后正常重试。
另一个场景加入 50,000 条遥测，由长读事务阻塞迁移并在 pg_stat_activity 中观察 Lock 等待；
锁超时后检查完整回滚和业务写入恢复，再以并发读写验证正常升级。
记录端到端迁移耗时和事务最大延迟；该规模是本地回归基线，不是生产容量承诺。

迁移连接默认 MIGRATION_LOCK_TIMEOUT_SECONDS=5、MIGRATION_STATEMENT_TIMEOUT_SECONDS=60，
仅作用于迁移连接，不改变应用连接池。可按已测数据量调整；超时后先确认回滚再重试。
连接共享和事务测试采用 [Alembic 官方连接共享方案](https://alembic.sqlalchemy.org/en/latest/cookbook.html#sharing-a-connection-across-one-or-more-programmatic-migration-commands)，
超时参数遵循 [PostgreSQL 16 文档](https://www.postgresql.org/docs/16/runtime-config-client.html)。
在线迁移在读取 Alembic Revision 之前获取固定数据库级事务 advisory lock；第二个迁移进程
等待首个事务结束后读取已提交的 Revision，避免重复执行同一 DDL。
超时和 application_name 使用事务局部配置，同时覆盖 CLI 与调用者提供的共享连接。
测试观察两个实际 advisory lock 等待者、确认两次升级均成功，再注入 pg_sleep 验证共享连接
语句超时、完整回滚、配置和锁释放及重试。
迁移要求 READ COMMITTED，并通过连续两条 SQL 的服务端事务 ID 证明事务有效；
连接级和引擎默认 AUTOCOMMIT、REPEATABLE READ、SERIALIZABLE 均有真实数据库拒绝测试。
这避免锁在语句结束时释放，或等待后继续读取旧事务快照。
共享连接已有事务时，由调用者负责最终提交/回滚；当前迁移均为事务 DDL，
包含 autocommit_block 或 CREATE INDEX CONCURRENTLY 的未来迁移需要单独设计维护流程。
锁语义见 [PostgreSQL advisory lock 文档](https://www.postgresql.org/docs/16/functions-admin.html#FUNCTIONS-ADVISORY-LOCKS)。

每一步保存前后 Revision、开始/结束时间、耗时、Schema 摘要、脱敏 Catalog 差异和五表摘要；
CI 额外强制检查失败回滚与规模/锁等待记录，不再仅接受几个 passed 字段。
独立测试容器承载全部破坏性权限和策略漂移测试，避免修改开发数据库权限。

现有本地 `database-before-tenant-bound.dump` 也完成了恢复、非超级用户升级及重复升级，
但五张业务表均为空，因此其结果只证明实际空库快照可升级。私有结果和原始备份均不上传 CI。
需要验收其他实际备份时，使用只读源文件及独立保存的摘要：

```powershell
.\.venv\Scripts\python.exe -m tests.integration.day12.private_backup_rehearsal <Day11备份路径> --sha256 <可信摘要> --output <新的报告路径>
```

该工具在专用容器中显式重建 Owner/ACL，再比较迁移前后数据；它不证明原始部署权限完全相同。
当前 CLI 支持本仓库 Day11 Schema；实际备份含扩展或自定义对象时需补充相应恢复配置。
摘要和输出路径在启动容器前验证。报告拒绝覆盖现有文件、源备份及其别名；
完整报告写入临时文件后，以不可覆盖的原子发布处理并发目标创建，原始备份保持只读。
省略 --output 时，每次使用 UTC 时间和 UUID 生成独立的 .runtime-reports/private-day11-upgrade-*.json，
并打印实际保存路径；原固定默认路径上的历史报告保留。
显式指定已存在的路径、输入备份或其别名时，CLI 在启动数据库前返回错误及退出码 2。
两个进程同时通过相同目标的预检后，原子发布仍只有一个成功，另一个拒绝覆盖；
真实双进程回归检查获胜者完整 JSON、原备份内容及临时文件清理。

专用身份及 API 启动方式见 [LOCAL_TENANT_RLS.md](LOCAL_TENANT_RLS.md)。
旧共享运行角色继续保留兼容模式；需要专用身份才能抵御主动修改租户会话上下文。
Migration/备份管理身份仍属于可信管理边界。

## 12B：权限配置矩阵的边界

矩阵使用实际 LocalStack Role 策略，拒绝 wildcard、额外策略和不受支持的条件。
本地检查器仅实现本仓库使用的精确 Action/Resource 与 StringEquals 子集，
不作为应用授权组件或通用 AWS IAM 模拟器。

36 项 Secret 检查中只有六项允许；36 项 KMS 配置检查中只有六项允许。
数据库身份与 Secret 归属也逐一验证。LocalStack IAM 执行并不等同于真实 AWS，
报告始终保留 `iam_enforcement_verified: false`。真实 AWS 中 AssumeRole 后的正负向请求，
以及完整每租户 SQS 路由部署，属于后续独立验收。

## 12C：五类完整告警

- DeviceAuthenticationBlocked：持久化认证失败次数耗尽，受审计重放并交付后恢复。
- VehicleCommandOrderStalled：独立测试库中注入过期的未终态命令，清理测试夹具后恢复。
- DeviceLedgerCapacityWarning：真实账本使用量超过配置额度 80%，扩展测试容量后恢复。
- RuntimeReportDeliveryStalled：注入创建时即延迟的设备报告，交付后恢复。
- RuntimeCollectorUnavailable：配置不存在的账本路径使真实采集失败，修复路径后恢复。

测试使用生产仓库的规则和路由配置，不直接伪造 Prometheus 指标或发送测试告警。
Webhook 为隔离网络中的本地接收器，没有外部消息发送。
容量使用每设备最大占用比例，避免一个设备满额被其他空设备的容量掩盖。
生产中禁止为解除告警而删除业务命令，未知执行结果必须先对账。

监控身份只能调用匿名聚合函数，不能读取业务表、继承其他角色或创建对象；
权限异常会使采集失败并触发告警。实际运行需配置全部目标设备账本路径和正确容量。

## 12D：可校验恢复

先使用 maintenance 工具生成快照，并将输出中的 SHA256 保存在可信的独立记录中。
恢复要求封存备份，没有活动 WAL/journal 文件；目标必须是新路径，不覆盖运行中的账本。

```powershell
.\.venv\Scripts\python.exe -m simulators.vehicle_device.maintenance --source .device/tbox.sqlite --destination .device/backup.sqlite
.\.venv\Scripts\python.exe -m simulators.vehicle_device.maintenance --source .device/backup.sqlite --destination .device/restored.sqlite --expected-sha256 <已保存的摘要> --operation-id <UUID> --actor local-operator --reason "verified recovery"
```

工具验证来源摘要、SQLite 完整性及复制期间来源未变化，在临时文件中写入恢复审计，
随后原子发布。摘要只能检测相对可信记录的内容变化，不能代替签名或备份访问控制。
恢复目标保留原事件审计，新增 maintenance_audit 记录操作者、原因、操作 ID、来源摘要和时间。
在线归档的相同命令 ID 如已有不同摘要则拒绝清理，不丢弃冲突证据。

物理断电、磁盘控制器损坏、异地灾难与零 RPO 均不在模拟验收证明范围内。

## 重复运行与发布

```powershell
$env:DAY12_EVIDENCE_RUN_ID = [guid]::NewGuid().ToString()
$env:RUNTIME_EVIDENCE_DIR = ".runtime-reports/day12-$env:DAY12_EVIDENCE_RUN_ID"
.\.venv\Scripts\python.exe -m pytest tests/integration/day12 tests/integration/security/test_database_runtime_permissions.py tests/unit/simulators/test_verified_restore.py -q
if ($LASTEXITCODE -ne 0) { throw "Day12 tests failed" }
.\.venv\Scripts\python.exe -m scripts.day12_evidence --directory $env:RUNTIME_EVIDENCE_DIR
```

下载 CI 产物后，可向 validate 函数显式传入从 GitHub 核对的 expected_commit 和 expected_run_id；
CLI 对应 --commit 和 --run-id。旧版无批次记录的历史产物不满足新 Gate，仍可作为历史证据保存。

测试自动创建并清理专用容器和网络，不删除开发环境卷。
Runtime CI 包含上述验收、原有单元/契约/设备全链路和可靠性测试。
IaC CI 保留验证、安全扫描、模块契约、计划策略、临时 LocalStack apply 与第二次无变化检查。
main 保持两项必需 Gate、strict 更新和管理员约束；合并不绕过保护。
