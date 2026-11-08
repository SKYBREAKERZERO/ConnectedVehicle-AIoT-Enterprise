# Day22 — Runtime / IaC 两小时收敛验收

日期：2026-10-21。PR：[#15](https://github.com/SKYBREAKERZERO/ConnectedVehicle-AIoT-Enterprise/pull/15)。本次只修复 Day21 遗留 CI 与证据问题，不新增 Campaign 功能、压测框架或数据库迁移。

## 已定位的失败与修复

| 问题 | 修复与边界 |
|---|---|
| Bootstrap AWS Provider 6.69.1 在 Linux 缓存校验失败 | 保留版本和全部校验要求，通过 Terraform 官方命令补齐 Linux 与 Windows 锁文件校验值。初始化继续使用 `-lockfile=readonly`。 |
| IaC 缓存可能混入开发目录 Provider | 运行在临时复制目录，只使用下载缓存；不复制开发目录的 `.terraform`、State、Plan、变量或密钥。缓存隔离和凭证清理回归测试继续执行。 |
| 旧 LocalStack 3.8.1 不返回 S3 生命周期字段，导致 Provider 等待超时 | IaC 沙箱固定到已经验证的公开 LocalStack 4.14.0 镜像摘要；保留生命周期、加密、版本保留和删除保护规则。没有付费令牌要求。 |
| Day12 Evidence 校验器与单元测试夹具的 Alembic Head 不一致 | 校验器和正常夹具均使用 `b16f238d45ac`，继续拒绝错误版本、缺失安全断言和异常权限证据。 |
| Day21 PostgreSQL 初始化阶段出现 ConnectionResetError | Docker 镜像的临时初始化服务可先接受 Unix Socket，但随后会退出重启。夹具改为检查容器内 `127.0.0.1` 的 TCP 服务，等正式实例启动后再 Bootstrap。仍使用真实 PostgreSQL，不 skip 或 mock 数据库测试。 |

## 保留的门禁

- Runtime 继续执行全仓 Ruff、格式、Mypy、设备契约、数据库迁移、单元/契约、真实权限与独立进程测试。
- Day21 的 13 项 PostgreSQL 并发、租约、幂等、暂停、死锁和权限测试单独执行并上传 JUnit XML。
- Day12、Day16、Day17、Day18、Day19 证据校验器继续强制执行，缺失、过期、错误 SHA 或错误 Run 的证据必须失败。
- IaC 继续执行 Terraform 初始化/验证/契约、安全扫描、计划策略、隔离 LocalStack 部署与重复计划检查。真实 AWS Organizations 有效性不在本次验收范围内。
- 主分支 Required Checks 仍为 `IaC quality gate` 和 `Runtime quality gate`，严格要求分支跟上基线。没有删除检查、修改分支保护或增加 `continue-on-error`。

## 最终确认方法

以当前 PR Head 为唯一目标，验收时重新查询 GitHub，不能使用历史绿色 Run 替代：

1. 两个 Workflow Run 的 `head_sha` 都必须等于当前 PR Head，且最终结论均为 `success`。
2. Runtime 的 Day12、Day16–19 验收步骤和 Day21 PostgreSQL 步骤均须成功；下载该 Run 的对应 Artifacts，不能拼接不同批次的证据。
3. 同一 Runtime 批次内部的 Commit 与 Run ID 必须一致。PR 工作流的证据可能记录 GitHub 合成的 Merge SHA；此时核查该 Merge Commit 包含目标 PR Head，不能把它误判为源代码不一致。
4. IaC 和 Runtime 是两个工作流，因此各自有独立 Run ID；两者通过相同 PR Head 关联。不能强制它们的 Run ID 相等。
5. IaC 成功摘要应为 `status=passed`、`security_scan=passed`、`resolved_plan_policy=passed`、`destroy_actions=0`、`second_plan_exit_code=0`，并确认 OTA 沙箱重复计划通过。
6. 保存下载文件的 SHA256、Run 链接、目标 Head、PR Required Checks 和本地质量结果。最终执行记录保存在忽略目录 `.runtime-reports/day22/`，不把运行中的状态预先标记为通过。

## 本地复跑

```powershell
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe -m mypy .
.\.venv-iac\Scripts\python.exe -m pytest -c scripts/iac/pytest.ini tests/unit/iac -q
.\.venv\Scripts\python.exe -m pytest tests/unit/test_day12_evidence.py tests/contract/test_ota_migration_lineage.py -q
.\.venv\Scripts\python.exe -m pytest tests/integration/day21 -q --junitxml=.runtime-reports/day22/day21-postgres.xml
git diff --check
gh pr checks 15
```

完整 IaC 和 Runtime 以本次 GitHub 运行结果确认，不能用上述本地静态检查代替。

## 交付边界

本次不执行真实 AWS Apply/Destroy，不升级现有开发数据库，不合并 PR。此前遗留的本地未跟踪 Provider 锁文件及空 `--json` 文件保留原样，不混入本次提交。源码修复和本说明采用明确文件列表提交，验收完成后再次核对工作区没有意外改动。
