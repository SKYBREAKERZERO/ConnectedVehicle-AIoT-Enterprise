# Day21 — Campaign Dispatcher 并发与恢复

日期：2026-10-20（日本时间）。范围为今天的 2 小时版本：数据库并发领取、幂等恢复、真实 PostgreSQL 故障测试；不包含大规模压测或生产发布。

## 实现

- 新增单线迁移 `b16f238d45ac`，父迁移 `a05e127c349b`。所有既有迁移文件和 Day19 SQL 合约源保持不变。新增 `dispatch_owner` / `dispatch_until`、成对空值约束和运行中 Campaign 索引。
- 受限 `SECURITY DEFINER` 领取函数按 Campaign 执行 `FOR UPDATE SKIP LOCKED`。不同 Worker 领取独立 Campaign，同一 Campaign 的 Wave 创建仍在现有事务锁下串行化。领取成功后立即提交，不在 S3/签名验证期间持有数据库事务锁。
- 租约默认 150 秒，长于 Worker 的 120 秒处理期限。崩溃后租约到期可重领；原所有者只能释放自己的租约。相同令牌重试领取可恢复已提交但响应未知的领取。
- 已失效 Worker 的 Tick 和自动 Pause 都在数据库行锁取得后核对租约，拒绝旧令牌。人工签名控制命令仍可暂停 Campaign。暂停与 Tick 由同一 Campaign 锁排序，不为后续 Wave 创建 Job；已有 downloading/installing 任务继续保留。
- 复用既有唯一约束：目标主键 `(tenant_id,campaign_id,ecu_id)`、目标 Job 唯一键 `(tenant_id,job_id)`、Job 幂等键 `(tenant_id,idempotency_key)`、ECU 活跃 Job 唯一索引和操作事件键 `(tenant_id,operation_id)`。Job 创建、目标 dispatched 标记、Wave 推进和审计事件同事务提交。
- SQLSTATE 分类：55P03 锁超时、40P01 死锁、40001 串行化失败、57014 语句超时、08003/08006 连接丢失。整笔事务最多尝试 3 次，带有抖动的短指数退避，复用同一请求及操作 ID；耗尽后返回依赖错误，不把数据库竞争误写成 Campaign 业务暂停。业务冲突仍进入受租约保护的暂停流程。
- 应用角色仅获新函数 EXECUTE；不增加 Campaign、租约字段或 Job 敏感状态的直接写权限。运行时启动校验同时验证新函数体、所有者、固定 search_path 和非 PUBLIC 执行授权。
- Worker 成功处理后重置连续失败计数。API 和 Dispatcher 暂时继续使用现有 tenant-bound application 数据库角色；独立 Campaign 数据库身份仍是后续工作。

## 最小真实 PostgreSQL 验收

测试每次创建独立 PostgreSQL 16 容器，使用完整 Alembic 迁移及真实受限 tenant 连接；结束后仅移除自己创建的容器。Docker 不可用或数据库测试失败时直接失败，不 skip，不使用 SQLite 替代数据库。

13 项 PostgreSQL 测试覆盖：

1. 唯一数据库 Migration Head、运行时安全校验、直接写状态/租约/目标及读取密钥被拒绝，跨租户领取被拒绝。
2. 同 Wave 两个调度事务和同 operation_id 重放，只产生一个逻辑 Job 和一条 Job 创建审计。
3. 逐 Wave 推进，未完成任务阻止前进，最终四个 Wave 无跳过、无重复。
4. 实际 Dispatcher 入口遇到被锁 Campaign 跳过，保持 running，不误暂停。
5. 独立子进程在 Job 提交后硬退出，重新执行原操作恢复原结果。
6. 行锁占用时 SKIP LOCKED 分配另一个 Campaign；竞争同一 Campaign 仅一个令牌获得领取。
7. 数据库连接被终止，未提交领取回滚，可立即重新领取。
8. 独立进程领取提交后硬退出；租约到期重领，旧令牌不能推进 Wave 或释放新租约。测试使用 1 秒租约；生产默认仍为 150 秒。
9. 真实 TCP HTTP 故障端点在服务事务提交后丢弃响应；重放原操作只保留一个 Job / 创建审计。该端点用于注入响应丢失，不替代生产 API 鉴权测试。
10. 未提交 Pause 与独立连接 Tick 实际竞争，Pause 提交后 Tick 不新增 Job。
11. 受控管理员预置在途状态后，Pause/Cancel 不关闭 downloading Job；完整鉴权设备 Claim/恢复由 Day19 主集成测试覆盖。
12. 真实行锁超时经过三次事务尝试后停止，Campaign 不误暂停，锁释放后重试成功。
13. 两个连接构造真实 PostgreSQL 死锁，受害事务整体回滚并成功重试。

## 执行结果

最终数字和日志指纹见 `.runtime-reports/day21/summary.json`；主要日志与 JUnit 文件位于同目录。

- Day21 PostgreSQL：13 passed（19.37 秒）。
- 全仓 Ruff check / format check：通过（447 个文件符合格式）。
- 全仓 Mypy：416 个源文件通过。
- Day17 本地规则与版本化设备契约检查：通过。
- 完整 unit + contract：1095 passed（119.42 秒）。
- Day19 真实 API / Dispatcher / 设备主流程：1 passed（44.21 秒）。
- git diff --check：通过；既有迁移文件无 diff；唯一 Head 为 b16f238d45ac。

## 复跑

在项目根目录执行：

```powershell
.\.venv\Scripts\python.exe -m alembic heads
.\.venv\Scripts\python.exe -m pytest tests/integration/day21 -q --junitxml=.runtime-reports/day21/postgres.xml
.\.venv\Scripts\python.exe -m pytest tests/unit tests/contract -q
.\.venv\Scripts\python.exe -m pytest tests/integration/day19/test_campaign.py -q
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe -m mypy .
git diff --check
git status --short
```

CI 新增 Day21 PostgreSQL 必跑步骤及 JUnit 证据上传，无 continue-on-error。完整 GitHub CI 尚未触发。

## 验收边界与交付

- 本次新增迁移仅在独立测试数据库执行；已有开发数据库没有被升级、清空或重新初始化。正式启用新 Dispatcher 前需用独立 migration_owner 凭证升级相应数据库至新 Head。
- 单独运行整个 Day19 测试目录时，其历史证据验收因缺少 `RUNTIME_EVIDENCE_DIR` 及 Day16–18 同批前置证据而失败；真实 API/Dispatcher/设备主集成用例本身通过。未伪造前置证据，也未将本次声明为完整 Runtime 验收。
- 当前分支保留 Day20 原有未提交改动；没有创建提交、推送或合并 GitHub。Commit/Push 按分工留给用户。
- 未改动同时出现的 `infra/day21/terraform` 文件；它们不属于本次 Runtime 修改。
- 没有执行真实 AWS Apply/Destroy，也未调用生产 AWS 资源。

## 今日 7 项清单

- [x] 唯一 Alembic Head，既有迁移不被修改。
- [x] 两个 Dispatcher 并发不重复创建逻辑 Job。
- [x] Commit 后响应丢失可幂等恢复。
- [x] Campaign 暂停阻止后续 Wave 新增下发。
- [x] 锁超时与真实死锁有界处理，不无限重试。
- [x] 真实 PostgreSQL 集成测试通过。
- [x] Ruff、pytest 与证据记录完成。

这些勾选对应本次本机开发验收；完整 Runtime 门禁、正式数据库升级及 Commit/Push 仍按上面的交付边界执行。
