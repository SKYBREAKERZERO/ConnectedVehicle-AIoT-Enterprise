# Day11 安全与运维补强

## 每车顺序

权威顺序为 PostgreSQL 的 dispatch_order；相同租户/车辆的发行事务使用事务级
advisory lock。跨 Publisher 都必须等待前序命令终态，才发布下一命令；不同车辆互不阻塞。
SENT / ACKNOWLEDGED 不是终态。发布超时可以重复同一命令，设备账本保证去重。

前序结果长期缺失时，不能直接将其标记 succeeded 来解除阻塞。先对账云端、T-Box、
Gateway、ECU；确认终态后使用带审计的既有操作工具。执行结果不确定时人工核验，
不可将超时视为未执行证明。等待命令继续使用 SQS 重试，达到队列接收次数上限可能
进入 DLQ；修复前序后按既有 DLQ 审核流程恢复。此策略优先保证执行顺序，牺牲单车
流水线吞吐。直接写库或绕过 dispatch service 的 Publisher 不属于受支持入口。

## 认证失败终止与告警

T-Box 401/403 保留短期 Token 轮换重试；第 8 次失败持久设置 blocked，错误码为
AUTH_RETRY_EXHAUSTED，并发出 ERROR 日志。重启不能清除次数；ACK blocked 时终态
报告不可领取。修复 Token 后停止 T-Box，使用已有按事件、操作 ID、操作者、原因、
租户/车辆约束的重放工具，再启动。重放不会清空历史次数。

运行 --reconcile 的 health.auth_blocked_reports 应为 0；非零立即告警。
log ERROR 由部署的日志采集器接入告警渠道，当前仓库不宣称已部署 AWS 告警服务。

## 账本容量与归档

DEVICE_MAX_LEDGER_RECORDS 默认 100000，涵盖命令记录、归档去重摘要与操作审计，达到上限拒收
新命令并保持 MQTT 未 ACK；DEVICE_MIN_FREE_BYTES 继续保护磁盘空间。
每小时采集 reconcile：记录数达到额度 80%、磁盘剩余不足两倍 reserve，或未交付报告
超过约定 SLA 时预警；达到 95% 时安排维护。保留策略由项目数据合规要求决定。

归档必须停 T-Box。示例：

```powershell
.\.venv\Scripts\python.exe -m simulators.vehicle_device.maintenance --source .device/tbox.sqlite --destination .device/archive-001.sqlite --archive-before 2026-10-01T00:00:00+00:00
```

工具取得维护锁，先在线 backup + integrity_check + 原子发布，再于单事务中清理最多
1000 个过期且已终态、报告全部 delivered 的命令及报告。保留身份、全部操作审计、
命令 ID 和原始规范化 Payload SHA256 去重摘要；重复命令拒绝再次执行，冲突正文拒绝。
最后 checkpoint/VACUUM 回收页面。未完成/blocked 记录不清理。重复运行须使用新目标。

归档文件含敏感业务数据，应使用受限主机权限、加密备份和定期离线恢复验证；文件不入 Git。
摘要和审计不自动删除，容量硬限避免无限增长；达到额度需审核后增加容量或设计新的
设备服役周期/归档索引，不能自行丢弃去重证据。

## 故障证据边界

E2E 增加 Broker SIGKILL 后重连并完成新命令；保留原有离线队列正常重启恢复。
磁盘损坏测试真实覆盖 SQLite 文件头被破坏、拒绝启动、拒绝发布损坏备份，以及从
先前验证过的快照恢复身份、ACK 顺序和去重。它们属于进程故障和逻辑磁盘损坏注入。

Broker 突然断电可能丢失尚未刷盘的会话/队列；MQTT PUBACK 不等价于灾难耐久性。
设备磁盘丢失且没有最新备份可能丢失执行去重证据。两种情况都必须保持命令未知/待对账，
停止盲目重发，按成组恢复要求核验 ECU 与云端账本。当前证据不覆盖物理断电、控制器
损坏、异地灾难、零 RPO 或真实 CAN；不得把模拟测试写成物理灾难恢复认证。

## GitHub 交付证据

[PR #3](https://github.com/SKYBREAKERZERO/ConnectedVehicle-AIoT-Enterprise/pull/3)
为 Day11 交付入口。Runtime / IaC 成功必须对应最新 head SHA；合并后还需核对 main
上的两条工作流。历史文档中的测试数字和未完成状态是当轮快照，不能替代最新远程验收。
本地 .runtime-reports/day11-github-acceptance.json 保存分支与 main 的提交、Run ID、
结果和已下载产物。main 强制两项检查、strict 更新与管理员约束。真实 AWS 后续验收。
