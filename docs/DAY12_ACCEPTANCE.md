# Day12 本地安全、恢复与发布验收

范围限定为本地 PostgreSQL、SQLite、免费 LocalStack 镜像、Prometheus 和 Alertmanager。
不部署真实 AWS，不调用付费云资源。本文件定义验收口径；实际结果以对应提交的
Runtime/IaC 检查和 `day12-local-acceptance` 产物为准。

| 阶段 | 实现与验收 | 证据文件 |
| --- | --- | --- |
| 12A | 固定每租户登录身份、最小 GRANT、禁止 DDL；六个角色跨租户读取拒绝、更新零行、插入拒绝；策略语义漂移被发现。新库与旧库升级到相同策略，重复升级无变化、原有记录不变。 | day12-12a-migrations.json、day12-12a-rls.json |
| 12B | 六角色 × 六 Secret 配置矩阵，仅允许各自 Secret；每角色验证正确及错误的 KMS 上下文、服务、Region 和 Key。读取实际 LocalStack 策略及 Secret KMS 绑定；正确/错误加密上下文执行真实本地 KMS 加解密检查。 | day12-12b-identity-matrix.json |
| 12C | 从真实 SQLite/PostgreSQL 收集指标，五类告警分别观察 Prometheus FIRING、Webhook firing、恢复后的 Webhook resolved，并关联同一次告警。 | day12-12c-alert-lifecycle.json |
| 12D | 备份 SHA256、完整性校验、恢复前摘要比对、设备归属、命令去重、ACK 前置顺序、事件重放审计和恢复操作审计；审计失败时恢复文件不发布。 | day12-12d-restore.json |
| 12E | Ruff、格式、mypy、pytest、迁移、Terraform 验证、安全扫描、模块测试和计划策略全部通过；两条必需 CI 通过后合并 PR，再核对 main。 | day12-acceptance.json、iac-gate-summary、GitHub 检查 |

所有运行证据、私有备份、SQLite 文件和 Terraform state 放在被 Git 忽略的目录。
CI 上传的 JSON 不包含数据库密码、Token、SecretString 或 Terraform state。
`scripts.day12_evidence` 要求全部阶段记录存在，验证告警实例和结果，再生成文件摘要清单；
缺失任何记录会使 Runtime Gate 失败。

## 12A：迁移与租户隔离

历史 e15c849a320b/f26d950b431c 迁移使用对应版本的 SQL 快照。
新增 b48f720da63e 同样读取固定快照，后续修改运行时 provisioning SQL 不会改变旧迁移。
新库从空库升级；旧库从 a37e610c952d 升级，并验证既有车辆完整记录不变。
独立测试容器承载全部破坏性权限和策略漂移测试，避免修改开发数据库权限。

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
.\.venv\Scripts\python.exe -m pytest tests/integration/day12 tests/integration/security/test_database_runtime_permissions.py tests/unit/simulators/test_verified_restore.py -q
.\.venv\Scripts\python.exe -m scripts.day12_evidence
```

测试自动创建并清理专用容器和网络，不删除开发环境卷。
Runtime CI 包含上述验收、原有单元/契约/设备全链路和可靠性测试。
IaC CI 保留验证、安全扫描、模块契约、计划策略、临时 LocalStack apply 与第二次无变化检查。
main 保持两项必需 Gate、strict 更新和管理员约束；合并不绕过保护。
