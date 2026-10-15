# Day15：数据库凭据生命周期

范围：PostgreSQL 16 与免费 LocalStack。没有运行真实 AWS；本地证据不证明 AWS IAM 强制授权。
Day15 分支从 Day14 已验收提交 `a8025ad477111107558d89c643b849714c732ab0` 建立；
Day14 PR 尚未合入时，Day15 包含其依赖变更。

## 创建与启用

Terraform 预创建 Secret 容器；本地租户示例仍有显式资源创建步骤。
Bootstrap 管理数据库角色，migration_owner 管理 Schema，三个运行身份只获得各自权限。
轮换服务不会隐式创建 Secret，不会恢复已计划删除的资源，也不会获得 DeleteSecret 权限。
第一次启用允许空容器，但数据库角色必须没有未知的现有密码。
首次版本可能自动成为 AWSCURRENT；三个运行进程必须等整组完成才能启动。

## 资源与旧操作隔离

轮换前检查整个目标组的资源身份、DeletedDate、版本 ID 与标签结构。
AWSCURRENT、AWSPENDING、AWSPREVIOUS 各自至多属于一个版本，拒绝重复标签。
任何 Pending 都阻止新轮换，包括同时挂在 Current 上的 Pending；不假定它已经完成。
只读拒绝发生在候选发布、数据库密码变更和操作日志创建之前。
通用 Provisioning 也在角色/Schema 操作前拒绝未完成 Pending。

新操作使用独立 UUID 操作 ID 与每个 Runtime 独立候选版本 ID。
旧的未完成日志只能操作其配置绑定的版本，不能清理外来 Pending。
已完成日志重复恢复是无操作；不会回滚之后的新轮换。

## 状态机与对账

正常状态：preparing → prepared → database_changed → verified → promoting → retiring → complete。
Prepare 保存所有候选；Verify 修改整组数据库密码后逐个登录验证；
Promote 将三个 Current 切到候选，并再次验证 Current 与数据库登录一致。
Retire 只去掉本次候选的 AWSPENDING；保留 Current、Previous 及其他标签，不删除版本。

发布前失败进入 recovering，原密码与原 Current 对账后进入 recovery_verified，
清理本次 Pending 后成为 recovered。补偿失败进入 recovery_required，保留日志供显式恢复。
候选版本发布响应必须匹配请求版本；全部 Prepared 版本的 Pending 归属、Current 与 Payload
在数据库密码修改前再次检查。清理全部标签后，再对账所有 Current/Pending 才写终态。
恢复退役分支也会在登录验证之后重新读取源日志，避免验证期间的文件替换被覆盖。
清理本身失败与密码变更失败分开处理：

- retiring 阶段失败：新密码和 Current 已经一致，恢复再次验证后继续清理，完成为 complete。
- recovery_verified 阶段失败：旧密码和 Current 已一致，恢复再次验证后继续清理，完成为 recovered。

上述清理重试不会重新写入密码。拒绝外来 Pending、计划删除、配置或版本异常。
进程在状态写入之间中断时，依靠已记录版本与实际标签重新对账；不能仅凭日志阶段宣布完成。

## 并发、恢复与审计

生产管理入口用 password_manager 持有 PostgreSQL Session Advisory Lock，
直到整个轮换/恢复结束；不同目标组也在同一管理数据库串行。
跨数据库或绕过管理入口的外部 AWS 发布不受这个锁约束。对版本再次检查可检测部分竞态，
Secrets Manager 没有跨三个 Secret 的原子事务；管理工具仍需作为唯一发布入口。
取得管理锁之前失败不会改写日志。软取消会等待已发出的线程云请求结束，
并完成解锁及连接池关闭后才传播取消，避免网络请求仍在执行时另一个管理操作进入。
这可能延迟取消至 SDK 请求超时；进程强杀与网络之外的物理故障仍需依据日志重新对账。

现有恢复命令不变：先停相关进程、开启维护模式并使用匹配环境/租户/Secret 配置，
再执行 `python -m database.provision_runtime_credentials --recover <操作日志.json>`。
日志不能自行取得权限。Day14 v2 日志继续支持；Day15 增加 events、promoting、retiring 与 recovery_verified。
事件含连续序号、带时区的时间、状态、动作和故障类型；操作 ID、Runtime 与版本关联由日志条目提供。
恢复日志保留最多 64 条近期事件，较早事件存入同目录 audit/ 下的不可覆盖分段文件。
分段按操作 ID、累计序号与 SHA256 命名，并链接上一段摘要。恢复前完整校验摘要、序号、
操作归属、状态转换及分段衔接；归档缺失或损坏时，在连接数据库之前拒绝。
恢复与备份必须一起保留日志及 audit/ 目录。旧 v2 未分段日志继续兼容。
每个文件限制 64 KiB，最多读取 1024 段以限制异常输入资源消耗；不提供无限容量或断电零丢失保证。
原子替换、文件刷新和状态转换检查保护日志写入，事件不包含密码或密码摘要。
这些管理文件仍是受信管理边界，不提供数字签名或防管理员篡改保证。

Day14 已完成但残留 Pending 的旧操作不会被新轮换覆盖。
新增显式 `--retire` 入口：原操作必须为 complete/recovered，所有 Current、数据库登录、
配置身份与候选版本归属均匹配后，才清理该操作的 Pending。它不改变原终态、不写数据库密码。
支持部分清理失败后安全重试；审计使用 pending_retirement 状态与 retire_pending 事件。
发现后来操作或外来 Pending，先拒绝，不替换旧标签。普通 --recover 仍保持终态幂等；
终态若存在未完成的显式退役，会提示使用 --retire。

```powershell
$env:CREDENTIAL_ROTATION_MAINTENANCE_MODE = "true"
.\.venv\Scripts\python.exe -m database.provision_runtime_credentials --retire <原操作日志.json> --scope runtimes
```

运行前需设置与原日志一致的本地数据库、租户、Region 与三个 Secret 配置；
--recover 和 --retire 互斥，--recover-scope 是 --scope 的兼容别名。

## 自动验收

单元测试覆盖 Pending 位于其他版本/Current、计划删除、资源身份与标签异常、
未完成操作隔离、非法状态跳转、成功保留 Previous，以及发布/回滚两种部分退役重试。
专用真实 PostgreSQL 16 和 LocalStack 容器验证：

- 外来 Pending 和计划删除拒绝前后，密码校验摘要和标签无变化。
- 第二个 Pending 清理失败后，恢复完成且密码摘要不变。
- 重复恢复无修改，Previous 保留，Pending 清空。
- 独立 PostgreSQL 会话无法取得已持有的锁，管理结束后可取得。
- 两个并发轮换均完成，操作 ID 独立且版本前后衔接、Current 唯一、无 Pending 残留。
- 真实管理锁超时后，日志、密码与 Secret 标签保持不变。
- 超过 128 条事件仍可恢复；被篡改的归档在恢复前被拒绝。
- 旧终态 Pending 显式退役及重复执行不写密码。
- 实际云请求被软取消时，独立 PostgreSQL 会话证明锁仍保持到请求结束。

证据是 `.runtime-reports/day12-credential-lifecycle.json`，CI 将它与其他十二份验收记录
按同一提交与 Run ID 检查，并计算文件摘要。任一生命周期断言失败都阻止 Gate 通过。
这是版本标签退役；禁用整个运行身份/租户、物理删除 Secret 和零停机轮换不在本次范围。

## 终态写入与审计边界补充

状态切换先写入完整检查点，成功后才替换内存状态。Complete/Recovered 写入失败时，
恢复入口仍保持 retiring/recovery_verified 路径；不把未持久化的终态写进 failed_phase，
也不因 Pending 已清理而丢失恢复能力。终态写入失败后的恢复不会再次改动已对账密码。
恢复的故障类型单独记录 recovery_failure_type，保留原始轮换 failure_type。

候选发布、回滚与显式旧版本退役，在标签清理后再次验证数据库登录与 Current；
清理期间发现数据库密码被外部改变时，不能宣布完成，也不会覆盖那个未知密码。
这些复核仍要求唯一管理入口；不能对绕过入口的外部管理员提供跨系统原子性保证。

审计在分段发布前验证完整记录与已有链，预计超过读取上限时拒绝新检查点，
保留原文件与内存记录，不生成工具自己无法读取的链。达到上限需保留并人工复核操作，
不能通过删除证据来解除限制。损坏、缺失及非法阶段不会先产生新的归档副作用。
测试新增成功发布与回滚两种终态磁盘写入失败、容量边界及旧 recovered 日志退役。

旧 v2 日志允许 failure_type/failed_phase 显式为空；新的恢复失败会填入有效故障元数据，
并继续保留可读取、可重试的检查点。旧 recovered 日志的 Pending 显式退役也有回归覆盖。

## 真实依赖与 KMS/IAM 专项边界

单元文件不启动 PostgreSQL 或 LocalStack；真实依赖验收位于以下独立文件：

- `tests/integration/day12/test_credential_lifecycle.py`：独立 PostgreSQL 会话锁争用、锁超时、两个管理操作串行，以及取消时管理锁保持。
- `tests/integration/day12/test_credential_cloud_contracts.py`：另一个实际 SDK 客户端在 Prepare 后抢走 Pending、在 Promote 期间抢走 Current。使用屏障控制真实服务操作时序；核对数据库密码摘要、外来版本标签与未完成日志，证明管理器不覆盖外部操作。
- 同一 cloud_contracts 专项另一个测试：创建、轮换、补偿恢复和旧版本退役前后，核对 IAM Role ID、Trust Policy、精确 Secret/KMS Policy、Secret 的 KMS 绑定及密钥启用/轮换状态，并实际执行 KMS 上下文正负向解密。
- `tests/integration/day12/test_identity_matrix.py`：六个运行身份的权限配置矩阵与跨身份上下文契约。

KMS/IAM 负向验收包括禁用密钥、关闭自动轮换、计划删除密钥、删除运行角色内联授权和 wildcard Policy；
验证契约拒绝并恢复原配置。没有删除运行角色或密钥实体，密钥计划删除会立即取消。

新增独立证据 `day12-credential-version-competition.json` 与
`day12-credential-cloud-lifecycle.json`；当前 Runtime Gate 必须检查同一批次的 13 份阶段证据。
LocalStack 验证的是实际版本/锁行为、KMS 上下文密码操作和 IAM/KMS 配置生命周期。
始终保留 `iam_enforcement_verified=false`，不把管理员客户端的成功读取当作运行身份 IAM 授权已强制执行，
也不声称已演练真实 AWS KMS 自动轮换材料或真实 AWS 密钥销毁。
