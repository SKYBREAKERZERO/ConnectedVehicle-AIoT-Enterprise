# Day14：凭据恢复输入安全与 Secret 缺失拒绝

验收范围仍为专用 PostgreSQL 容器与免费 LocalStack，不执行真实 AWS。
现有 Day14 分支基线为 `bc09dcefaaa7bb54dc351b62f6bfe76373926459`，工作树检查后复用。

## Secret 容器由部署流程预创建

`current_version()` 只读取已存在的 Secret。资源不存在立即拒绝，提示通过 Terraform
预创建；它不会调用 CreateSecret，也不会创建日志、修改数据库密码或发布版本标签。
已存在但没有当前版本的空容器仍允许首次发布，这与资源不存在不同。
通用 Provisioning 在角色或 Schema 变更前检查全部三个容器，轮换中也再次检查。

本地租户/监控示例的资源创建属于显式 LocalStack 部署步骤，仍限制本机端点；
凭据轮换和恢复不会借用示例创建资源。监控示例现在显式准备自己的 Secret 容器。
真实 AWS 的通用流程继续依赖 Terraform 资源与已有最小权限策略，没有新增 CreateSecret 授权。

## 恢复日志 v2

新操作写入版本 2 日志，绑定应用名、环境、Cloud Runtime、Region、LocalStack 端点、
租户、数据库主机/端口/库名，以及明确的身份范围。
默认范围是 `runtimes`，必须包含完整的 application、outbox、remote-command 三个条目。
角色与 Secret ID 从当前配置生成允许列表，日志不能自行指定迁移、Bootstrap 或其他租户身份。
显式 Secret ID 优先，否则使用与运行时加载规则一致的默认路径。

校验发生在数据库连接之前，并拒绝：

- 不正确的根结构、缺少字段、未知字段、重复 JSON 键和非有限数值。
- 布尔值/字符串/小数冒充整数版本或端口；未知日志版本、非法阶段。
- 非 UUID4 操作 ID、候选版本，非法旧版本或新旧版本相同。
- 缺失、多余、重复 Runtime、角色、Secret 或候选版本。
- 配置与日志的环境、数据库、租户或 Secret 目标不匹配。
- 超过 64 KiB、无法解析、非 `.json` 或符号链接输入。

版本 1 缺少完整环境绑定，不能直接使用新恢复入口。已有 v1 日志和旧 Secret 版本应保留，
经运维人员独立核对并形成符合当前配置的 v2 记录后再恢复；工具不自动给旧日志补填可信字段。
日志不是签名凭证。运维目录、当前配置与旧 Secret 版本仍必须由受控管理员保管，
不能据此宣称能抵御同时修改配置、日志或管理程序的管理员。

## 恢复前检查真实版本

数据库锁获取后重新读取并校验日志，避免并发恢复继续使用过期内容。
在修改任何密码之前，所有条目都必须完成服务端检查：当前版本属于所记旧/候选版本，
候选仍属于 AWSPENDING，旧版本对应当前或前一版本；读取响应的版本 ID、凭据结构、
角色、租户、数据库地址均匹配。准备阶段尚未写入的候选允许缺失，但不能由后续待发布版本替代。
候选尚未写入且没有旧版本时，数据库角色必须仍无密码；已有密码会使恢复拒绝，不能清空未知凭据。
这些读取结束后再次检查日志内容，输入被替换时拒绝，不覆盖被替换文件。

预检失败不修改密码、Secret 标签或日志。执行开始后的数据库/发布故障则保持
`recovery_required`，错误脱敏并保留重试入口。补偿和恢复都在同一个管理数据库的锁下协调。
重复恢复已验证为无变更；并发恢复在锁内重读完成状态，不重复更新密码。

三 Runtime 恢复命令：

```powershell
$env:CREDENTIAL_ROTATION_MAINTENANCE_MODE = 'true'
python -m database.provision_runtime_credentials --recover <v2日志.json>
```

固定租户恢复必须同时配置正确 DATABASE_TENANT_ID 和三份 Secret ID。
监控日志不能自行切换范围，需要操作员明确选择：

```powershell
python -m database.provision_runtime_credentials --recover <监控v2日志.json> --recover-scope observability
```

## 回归证据

单元测试检查静态非法日志在连接前停止，错误不泄漏输入，日志、密码、Secret 标签保持不变；
还覆盖云端预检期间输入替换、候选/旧版本绑定、恢复补偿失败、并发及重复恢复。
集成测试在真实 PostgreSQL/LocalStack 上覆盖 17 类非法恢复输入和版本负向场景，
比较全体数据库角色的密码验证器摘要、Secret 版本/内容摘要和日志字节。
摘要只用于内部断言，不上传密码验证器或 Secret 内容。

测试故意删除专用测试 Secret，分别调用轮换和恢复，证明资源仍不存在且密码未改变。
数据库补偿失败后执行合法显式恢复，并重复执行，确认不会产生第二次更新。
证据 `day12-credential-recovery-hardening.json` 绑定提交与 CI 批次，由现有验收器
作为新增必需阶段检查，并与其他 Day12/Day14 本地验收产物一起上传。

维护窗口、首次发布、旧版本保留与管理数据库范围约束继续适用，见
[DATABASE_MANAGEMENT.md](DATABASE_MANAGEMENT.md)。进程崩溃仍需要管理员检查未完成操作，
本次没有实现在线无中断轮换或日志自动恢复服务。
