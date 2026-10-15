# 数据库管理身份、凭据发布与验收

本次自动验收只运行本地 PostgreSQL 与免费 LocalStack。真实 AWS 工具已提供，未联网执行，
本地报告始终保留 `iam_enforcement_verified=false`。
Day14 的 Secret 缺失拒绝、v2 日志格式和无副作用回归见
[DAY14_CREDENTIAL_RECOVERY.md](DAY14_CREDENTIAL_RECOVERY.md)。旧 v1 日志不能自动恢复。

## 身份边界

| 身份 | 用途 | 权限边界 |
| --- | --- | --- |
| BOOTSTRAP_DATABASE_USERNAME/PASSWORD | 初始角色管理和受控密码变更 | 独立集群管理连接；本地示例为容器管理员 |
| MIGRATION_DATABASE_USERNAME/PASSWORD | Alembic 和 Schema ACL | `migration_owner`，拥有目标数据库，无 SUPERUSER/BYPASSRLS/CREATEROLE/CREATEDB/REPLICATION/INHERIT 或角色成员关系 |
| 三个 Runtime 身份 | API、Outbox、Remote Command | 各自 Secret、GRANT；每租户身份固定绑定租户，无 DDL |

管理员凭据不会回退到迁移凭据。管理模块在数据库端核对实际 session_user/current_user；
迁移连接即使通过 SET ROLE 切换成 Owner，也会因登录身份不符被拒绝。
`runtime-roles.sql` 只通过 Bootstrap 执行，`runtime-grants.sql` 只通过 Schema Owner 执行。
历史 Alembic SQL 快照保留，修改 provisioning 不会改变发布过的迁移。
Terraform 的 Secret Bootstrap 策略只对三个数据库 Secret 授予 Describe/Get/Put/
UpdateSecretVersionStage；KMS 仍限制 ViaService，并限定同一组三个 SecretARN 上下文。
该角色不能创建任意 Secret，容器由 Terraform 预先创建。Runtime 角色继续只能读取各自 Secret。

空库部署顺序如下，环境中需要显式配置两组独立管理凭据：

```powershell
python -m database.bootstrap_cluster
python -m alembic upgrade head
python -m database.provision_runtime_credentials
```

Bootstrap 只自动转移空库的数据库 Owner。已有业务对象且 Owner 不匹配时会拒绝；
已有部署需要先备份，检查对象、函数、Schema Owner、ACL 和迁移历史，执行经过审查的
所有权切换，再以 `migration_owner` 验证迁移。不要直接对已有开发数据库反复尝试自动切换。
本地集群管理员是可信边界；生产角色管理员需要具备对应角色的管理权及 pg_authid
密码是否存在的读取能力。缺少这些授权时应停止配置，不能改用迁移账号。

## 三份凭据的发布与恢复

PostgreSQL 单用户只有一个密码，因此当前采用维护窗口协议，不承诺零中断或跨系统原子事务。
先停三个相关 Runtime，并关闭连接池；已有凭据轮换显式设置
`CREDENTIAL_ROTATION_MAINTENANCE_MODE=true`。首次部署也必须等整个操作完成才启动 Runtime。

1. 检查全部旧 AWSCURRENT 的数据库地址、用户名、租户绑定、真实登录与安全权限。
   旧数据库密码存在但没有可恢复 Secret 时拒绝；需要显式处理历史凭据。
2. 给全部 Secret 写入 UUID 版本的 AWSPENDING，在脱敏恢复日志记录旧、新版本 ID。
3. 独立 Bootstrap 连接在同一 PostgreSQL 事务中更新全部密码。
4. 使用候选凭据逐个重新登录，检查权限和租户归属，通过后逐个提升 AWSCURRENT，复核标签。
5. 全部完成后重启 Runtime，确认启动检查通过；退出维护窗口。

首次写入会自动获得 AWSCURRENT，这是
[AWS PutSecretValue 的语义](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_PutSecretValue.html)。
首次部署必须停服务；既有凭据的候选版本只挂 AWSPENDING。新旧版本使用固定版本 ID，
重试和补偿不依赖可移动的 AWSPREVIOUS。成功后候选的 AWSPENDING 标签可以保留，
下一次候选写入会转移此标签。

发布或验证失败时恢复全部数据库旧密码和 Secret 当前标签，再验证旧凭据登录。
恢复失败则日志标记 `recovery_required`，不能启动 Runtime，也不能把失败当作成功。
恢复日志位于被 Git 忽略的 `.runtime-reports/credential-operations/<UUID>.json`，
只含身份、端点、版本 ID、阶段及异常类别，不含密码、Token 或 SecretString。
v2 日志还绑定当前环境及身份范围；非法输入在修改密码前拒绝，日志不能选择任意角色或 Secret。
将该目录作为受控运维资料保存，限制访问并防止误改；旧版本 Secret 在恢复完成前不能删除。

```powershell
$env:CREDENTIAL_ROTATION_MAINTENANCE_MODE = 'true'
python -m database.provision_runtime_credentials --recover .runtime-reports/credential-operations/<UUID>.json
```

恢复拒绝已被下一次轮换取代的版本。数据库级会话 advisory lock 序列化包括重叠角色集合在内的
发布与恢复操作；角色是集群级资源，部署必须统一通过同一个管理数据库协调角色变更。
进程崩溃或机器断电不会自动触发补偿，操作员须检查未完成日志并恢复；这不是零数据丢失保证。

CI 真实本地测试覆盖第二份候选写入失败、第二份标签提升失败、数据库补偿失败、
显式恢复、再次成功发布，以及三份旧密码和当前版本同时恢复。另有独立测试覆盖候选验证失败、
维护窗口门禁、不可恢复旧凭据、过期恢复日志及日志脱敏。

## 真实 AWS 工具：已补充，未执行

`scripts.aws_acceptance` 仍是配置检查，IAM Simulator 结果不能证明运行身份的实际授权。
`scripts.aws_runtime_probe` 默认只校验输入并输出 `not_executed`，不创建 AWS Session。
需要未来明确授权后才使用 `--execute`。目标文件需要 account、region、profile，以及
roles、secrets、kms_keys 三个映射，键为 api、outbox、remote-command，值为完整 ARN。
支持标准 AWS 分区的 Region；不接受 LocalStack、端点覆盖或默认账号猜测。
格式示例为 `config/aws-runtime-probe.example.json`，其中账号与 ARN 均为示例，不能作为部署证据。

离线检查：

```powershell
python -m scripts.aws_runtime_probe --target <目标JSON> --report <新的报告JSON>
```

启用后工具核对源账号，逐个 AssumeRole，以实际临时身份执行九格 Secret 正负向矩阵，
要求自己的 Secret 读取成功、另外两个明确 AccessDenied，并核对 Secret 的客户管理 KMS Key。
自己 Secret 的成功读取证明该 Key 经 Secrets Manager 的实际解密链路可用。
返回 NotFound、无效密文、网络失败等不能替代拒绝证据，报告不保存 Secret 内容或临时凭据。
不创建、修改、删除资源或信任策略；验收者必须已被允许 AssumeRole，服务专用信任拒绝验收者时
报告失败，不自动放宽信任。

可选 kms_ciphertexts 映射提供三个已有有效密文的 Base64。工具先用验收身份确认密文及
`SecretARN` 上下文有效，再要求 Runtime 的直接 KMS Decrypt 被拒绝，验证 ViaService 边界。
没有密文时 `direct_kms_boundary_verified=false`；不会为了测试生成密文或伪造完整验收。
API 语义参见 [AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)
和 [Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html)。
报告采用新文件创建，拒绝覆盖输入或历史报告。当前只运行模拟客户端测试，不执行真实 AWS 请求。

## Day15 lifecycle constraints

Existing AWSPENDING or scheduled Secret deletion blocks a new rotation. Completion and compensation
retire only this operation's Pending label, preserving Current/Previous. Retirement recovery verifies
passwords without rewriting them. See [Day15](DAY15_CREDENTIAL_LIFECYCLE.md).

Existing terminal Day14 journals with retained Pending can be explicitly reconciled using
`python -m database.provision_runtime_credentials --retire <journal.json> --scope runtimes`
in maintenance mode. The tool validates Current and database logins before removing owned labels;
it never resets a password. Preserve the journal and adjacent `audit/` segments together.
Lock acquisition failures preserve the journal. Soft cancellation drains in-flight cloud calls
before releasing the session lock. These checks do not assert physical power-loss durability.
