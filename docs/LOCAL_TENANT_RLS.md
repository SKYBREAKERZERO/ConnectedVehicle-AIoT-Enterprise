# 每租户独立身份：本地 RLS 示例

本示例只使用现有本地 PostgreSQL 和 LocalStack，不连接真实 AWS，也不创建付费云资源。
每个租户拥有 Application、Outbox、Remote Command 三个独立登录角色和三个 Secret。
角色名为原有运行角色名加租户 SHA256 的前 12 位；绑定表保留完整 tenant_id，并拒绝冲突。

## 数据库隔离

迁移 `b48f720da63e` 创建管理身份拥有的 `runtime_tenant_bindings`。
`runtime_tenant_binding()` 通过 `SESSION_USER` 查询固定归属，以固定 search_path 的
SECURITY DEFINER 函数返回单个租户。运行身份不能读取或修改绑定表。

五张业务表的 restrictive RLS 同时约束 USING 和 WITH CHECK。专用登录的固定绑定
优先于会话上下文，修改 `app.tenant_id` 无法切换归属。最小 GRANT 仍分别限制 API 表、
Outbox 分发列、Remote Command 状态列；运行角色没有超级用户、BYPASSRLS、角色成员关系、
建库、建表或临时表权限。Migration 使用独立管理凭据，专用运行角色也被禁止用作迁移身份。

启动检查精确核对策略数量、角色范围、命令范围、USING/WITH CHECK、辅助函数定义及
Outbox 生成列表达式。数据库角色、Secret 中的用户名和租户、进程配置中的租户必须一致。

旧共享角色继续使用会话上下文兼容模式，仍不能抵御共享凭据持有者主动切换租户。
只有切换到本例专用身份的进程才获得固定租户隔离。管理身份仍然可以访问所有租户。

## 创建与验收

先启动仓库的本地依赖，分别配置 BOOTSTRAP_DATABASE_USERNAME/PASSWORD 与
MIGRATION_DATABASE_USERNAME/PASSWORD。空库先执行 `python -m database.bootstrap_cluster`；
已有数据库的所有权切换见 [DATABASE_MANAGEMENT.md](DATABASE_MANAGEMENT.md)。
本地 Secret 端口由 AWS_ENDPOINT_URL 指定，数据库地址必须为 localhost 或 127.0.0.1。

```powershell
.\.venv\Scripts\python.exe -m alembic upgrade head
.\.venv\Scripts\python.exe -m database.provision_tenant_local --tenant local-tenant-a > .runtime-reports/tenant-a.json
.\.venv\Scripts\python.exe -m database.provision_tenant_local --tenant local-tenant-b > .runtime-reports/tenant-b.json
.\.venv\Scripts\python.exe -m scripts.verify_tenant_local .runtime-reports/tenant-a.json
.\.venv\Scripts\python.exe -m scripts.verify_tenant_local .runtime-reports/tenant-b.json
```

重复 provisioning 会轮换密码，先停进程并显式设置
`CREDENTIAL_ROTATION_MAINTENANCE_MODE=true`，成功后重新启动。
失败补偿与显式恢复见数据库管理文档。输出只含角色名、Secret 名称和
ARN，不含密码。密码、数据库备份、Terraform state 和验收文件留在被忽略的本地目录。

每个租户的进程分别配置 `DATABASE_TENANT_ID`；未显式设置 Secret ID 时，加载器自动选择
`/connected-vehicle/local/tenants/<租户哈希>/database/<runtime>`。显式配置的旧 Secret ID
不会被覆盖，必须清除或改为对应专用 Secret；错误身份导致启动失败。

以租户 A 的 API 为例，在独立 PowerShell 窗口中运行：

```powershell
$env:DATABASE_TENANT_ID = "local-tenant-a"
$env:APPLICATION_DATABASE_SECRET_ID = "/connected-vehicle/local/tenants/c6a79ee8cdcf/database/application"
$env:APP_PORT = "18000"
.\.venv\Scripts\python.exe -m apps.api
```

租户 B 使用 `local-tenant-b`、哈希 `a70d1799692b` 和另一个端口。
Outbox 和 Remote Command 使用各自的 Secret，入口分别为 `apps.outbox` 和 `apps.remote_command`。
本例验证数据库身份隔离；完整每租户部署还需独立配置队列路由和消息权限。
不能让多个专用 Worker 无差别消费同一个混合租户队列。

## LocalStack IAM/KMS 的证据边界

示例同时创建六个本地 IAM Role，每个 Secret 读取策略只包含自己的 Secret ARN。
KMS 解密仅指向示例 CMK，并限制 ViaService 和对应 SecretARN 加密上下文。
验收读取实际策略配置，验证 Secret 的 KMS 绑定、轮换，以及正确/错误上下文的加解密行为。

LocalStack 的 IAM 拒绝行为不等同于真实 AWS。结果明确记录
`iam_enforcement_verified: false`。本地进程使用 LocalStack 开发凭据，不宣称已部署
真实 ECS Task Role 或完成生产 IAM 授权验收。示例 IAM Role 仅提供 Secret/KMS 权限，
不是包含 SQS 等权限的完整部署角色。

## 当前验证

2026-10-11：全仓库 pytest 710 passed；Ruff 检查和格式检查通过；mypy 292 个源文件通过。
质量检查排除了先前存在的未跟踪工具 `apply_day11_rls_hardening.py`，未修改该文件。
真实 PostgreSQL 测试覆盖两个租户的六个角色、伪造会话归属、跨租户读取与更新、禁止 DDL、
绑定表保护和策略漂移。两个本地租户的专用角色、Secret 和 KMS 验收均通过。
随后补充专用 API 跨租户插入拒绝、全部角色绑定修改拒绝和错误租户启动拒绝断言，
相关真实数据库集成测试再次通过。两个独立 API 进程以不同租户身份同时启动，
均通过启动安全检查并返回健康检查 200；验收结束后已关闭这两个临时进程。
启动记录位于 `.runtime-reports/tenant-api-startup.json`。
Terraform local/dev validate、fmt，以及本地恢复 apply 后第二次 plan 无变化通过。

这些是 2026-10-11 的本地证据。后续分阶段与 GitHub 交付验收参见
[DAY12_ACCEPTANCE.md](DAY12_ACCEPTANCE.md)，以当前提交对应的 CI 产物为准。
