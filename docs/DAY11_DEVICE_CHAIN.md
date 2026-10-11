# Day11：持久化设备链路与三个独立设备进程

本阶段实现的是本地设备仿真。保留现有 API、Outbox、Remote Command 三个进程，
新增 T-Box、Gateway ECU 与 Body ECU 三个进程。设备端只需要 MQTT 身份和车辆范围的
OIDC access token；不读取 AWS Secrets Manager 或云端数据库凭据。

| 阶段 | 实现 | 自动验收 |
|---|---|---|
| D11-1 | T-Box SQLite command inbox + ACK/result outbox | 命令与 ACK 原子提交，提交后强制崩溃仍可恢复 |
| D11-2 | MQTT QoS1 subscriber + HTTP reporter | SQLite 提交后 PUBACK；签名设备身份回报 ACK 与结果 |
| D11-3 | Gateway、Body ECU 两个独立 ECU 进程，loopback virtual CAN | CAN 命令帧与结果帧跨进程交换；ECU 执行账本去重 |
| D11-4 | API → Outbox → SQS → MQTT → T-Box → Gateway → Body ECU → HTTP | LOCK 后 ECU locked=true，云端 command=succeeded |
| D11-5 | 四处崩溃、HTTP 中断、重复投递、离线 session、运维对账 | Runtime quality gate 强制运行真实依赖 E2E |

## 先决条件与启动

Python 3.12，安装 `python -m pip install -e ".[dev]"`。
先按 [现有运行时文档](RUNTIME_AND_E2E.md) 启动云端三个进程及 PostgreSQL、Redis、
SQS/LocalStack、MQTT broker，并在云端创建有效车辆。

设备 tenant_id 与 vehicle_id 必须对应云端记录。设备 token 文件存放有效的 RS256
OIDC access token（issuer、audience 与 API 配置一致，principal_type=device，
vehicle_id、tenant_id 与设备一致，scope 包含 command:report）。普通服务 token
不能回报设备结果。正式身份由身份提供方签发；E2E 使用临时 RSA 签名和受信公钥配置。

在第一个 PowerShell 窗口启动 Body ECU：

```powershell
.\.venv\Scripts\python.exe -m simulators.body_ecu `
  --database .device/body.sqlite --port 19001 --gateway-port 19003
```

在第二个窗口启动独立 Gateway ECU：

```powershell
.\.venv\Scripts\python.exe -m simulators.gateway `
  --database .device/gateway.sqlite --port 19002 --tbox-port 19000 `
  --body-bus-port 19003 --body-port 19001
```

Gateway 将 T-Box 接口与 Body ECU 接口分开，路由命令与结果分别提交 SQLite；
重启后继续转发 pending 命令，completed 命令返回缓存结果。

在第三个窗口设置设备身份与连接后启动 T-Box：

```powershell
$env:DEVICE_DATABASE = "$PWD/.device/tbox.sqlite"
$env:DEVICE_TENANT_ID = "your-tenant"
$env:DEVICE_VEHICLE_ID = "replace-with-existing-vehicle-uuid"
$env:DEVICE_API_URL = "http://127.0.0.1:8000"
$env:DEVICE_TOKEN_FILE = "$PWD/.device/device.jwt"
$env:DEVICE_MQTT_HOST = "127.0.0.1"
$env:DEVICE_MQTT_PORT = "1883"
$env:DEVICE_ALLOW_INSECURE_LOCAL = "true"
$env:DEVICE_CAN_PORT = "19000"
$env:DEVICE_GATEWAY_PORT = "19002"
.\.venv\Scripts\python.exe -m simulators.vehicle_device
```

将上述 tenant、vehicle、token 文件替换为实际值。等待日志 `body_ecu_ready`、`gateway_ready` 与
`device_mqtt_ready`，然后通过现有 API 下发 `{"command_type":"lock"}`。
设备自动发送 acknowledged、succeeded；GET command 接口使用有 vehicle:read 权限的
用户身份核对最终状态。支持 LOCK/UNLOCK；其他命令 ACK 后回报 failed /
UNSUPPORTED_COMMAND，不能将未实现的功能标为成功。

也可使用安装的 `vehicle-device-simulator`、`vehicle-gateway`、`vehicle-body-ecu` 入口。
每份 SQLite 文件只运行一个对应进程；四个 virtual CAN 端口必须互不相同。
Ctrl+C / SIGTERM / Windows CTRL_BREAK 可有序关闭；未完成回报保留在 SQLite。

## MQTT 与 HTTP 安全、持久化语义

- 默认要求 HTTPS 与 MQTT CA 验证。远端配置 DEVICE_MQTT_CA_FILE，以及可选的
  DEVICE_MQTT_CERT_FILE / DEVICE_MQTT_KEY_FILE、USERNAME/PASSWORD；证书与私钥必须成对。
  本地明文必须显式开启 DEVICE_ALLOW_INSECURE_LOCAL，且 API、MQTT 都只能是 loopback。
- MQTT 主题固定为 `tenants/{tenant}/vehicles/{vehicle}/commands`，QoS1、retain=false。
  接收端复用云端 DispatchPayload，验证车辆、租户、时间与大小，错误消息提交 quarantine 后
  才 ACK。相同 command_id 的不同内容会隔离，不能覆盖原始命令。
- 稳定 MQTT client ID，clean_session=false；先提交命令及 ACK outbox，再发送 PUBACK。
  aiomqtt 2.5.1 没有公开 manual-ACK 参数，因此适配层隔离调用其 Paho bridge；升级需要
  manual-ACK 回归测试。256 条接收队列溢出时断开并重连，让 broker 重投未 ACK 消息。
- ACK 和执行结果分别使用持久化的 event_id、occurred_at、payload；每个命令先 ACK 后结果。
  只有 HTTP 2xx 才标 delivered。连接错误、408、429、5xx 指数退避；401/403 也保留重试，
  每次从文件重新加载 token 以支持轮换。3xx 和其余 4xx 标 blocked，保留对账信息，禁止自动丢弃。
- SQLite 使用 WAL + synchronous=FULL；执行状态与执行账本同事务提交。
  T-Box 在 CAN 发送前保存尝试记录；响应丢失只重发相同命令，ECU 返回缓存结果。
  尚未尝试的过期命令失败；ECU 对新过期命令不执行，对已执行命令返回缓存结果。
  发送后超时属于结果未知，不能仅因超时或过期认定执行失败；保持 pending 供恢复和对账。
  T-Box 与 Gateway 按接收提交顺序串行处理；旧命令退避或结果未知时，后续命令不得越过。
  这保证设备端重试不会改变执行顺序；不证明云端多个 publisher 的全局下发顺序。
- Broker 必须启用持久 session，并为 broker 重启另行配置磁盘 persistence、队列容量、
  retention/expiry。E2E 已启用 broker persistence，并验证设备离线期间发布、broker
  有序重启后恢复补投；此证据不覆盖 broker 突然断电或磁盘丢失。PUBACK 不代表物理车辆执行。

## Virtual CAN 的范围

这是 loopback UDP transport，用于 Windows/Linux 跨进程测试，不是 python-can
内存 VirtualBus，也不是实车 SocketCAN。命令 arbitration ID=0x100，数据为
1 字节操作码（1=LOCK，2=UNLOCK）+ 6 字节大端 UTC expiry 毫秒；兼容旧 4 字节秒格式。结果 ID=0x180，
1 字节结果（0=成功，1=未支持，2=过期，3=内容冲突）。帧最多 8 字节。
T-Box(19000) ↔ Gateway(19002)，Gateway(19003) ↔ Body ECU(19001)。

command_id 位于 UDP 仿真 envelope 中，用于事务关联，不占用仿真 CAN data bytes；
物理 CAN 接入需要另外设计 ISO-TP/诊断会话关联、总线仲裁、认证与车规安全验证。
接收端限制消息长度、ID、数据长度、关联 ID、来源端口；UDP 仅绑定 127.0.0.1。
本地恶意进程不属于此仿真通道的安全边界；不能部署为远程 ECU 通信。

## 故障注入与对账

故障参数仅用于仿真：DEVICE_CRASH_AFTER=command_commit 或 result_commit，让
T-Box 在持久化后以 exit code 70 强制退出；Body ECU `--crash-after-execution`
在执行提交后以 71 退出；Gateway `--crash-after-route` 在路由提交后以 72 退出。每个 checkpoint 在对应 SQLite faults 表中只触发一次，
同一文件和参数重启不会无限崩溃。要重做注入，使用新的隔离测试目录。

```powershell
.\.venv\Scripts\python.exe -m simulators.vehicle_device --reconcile .device/tbox.sqlite
.\.venv\Scripts\python.exe -m simulators.gateway --database .device/gateway.sqlite --inspect
.\.venv\Scripts\python.exe -m simulators.body_ecu --database .device/body.sqlite --inspect
```

按 command_id 对比 T-Box、Gateway routes、Body ECU executions、云端 GET command；按 event_id 对比
云端 report ledger。pending 报告检查 API 连通性、token 过期、权限及重试错误码；
CAN pending 检查 ECU 可用性，保留原账本，不生成新 command_id 来掩盖未知结果。
blocked 检查冲突/Schema/时间或错误的身份配置，并确认云端实际状态。

修复原因并审阅后可执行：

```powershell
.\.venv\Scripts\python.exe -m simulators.vehicle_device `
  --reconcile .device/tbox.sqlite --requeue-blocked `
  --tenant-id "<provisioned-tenant>" --vehicle-id "<provisioned-vehicle-UUID>" `
  --event-id "<blocked-event-UUID>" --operation-id "<new-operation-UUID>" `
  --actor "local-operator" --reason "Cloud conflict reconciled"
```

此操作重排 blocked 报告，保留 event_id 和原 payload；不自动修改 payload、删除证据、
或重执行 ECU。quarantine 只列摘要和原因，需从可信云端来源核对并重新下发合法命令。
SQLite、WAL/SHM、token 文件不进入 Git；限制目录访问权限。部署时需设置持久卷、
磁盘容量告警、保留周期和备份策略；本阶段不自动清理去重账本。

## 自动验收

```powershell
.\.venv\Scripts\pytest.exe tests/unit/test_device_simulator.py tests/contract -q
.\.venv\Scripts\pytest.exe tests/e2e/test_device_full_chain.py -q
```

E2E 自动创建隔离 Docker PostgreSQL、Redis、LocalStack、Mosquitto，使用真实的
三个云端进程、三个设备进程、MQTT/HTTP/UDP 套接字、三个 PostgreSQL 运行角色，
不替换身份依赖；测试包括四处真实进程退出、HTTP 不可达、MQTT 重投、设备离线补投、
LOCK/UNLOCK 与不支持命令的 failed 结果，并核对云端最终状态。

临时目录生成 day11-evidence.json 与 resilience-evidence.json；CI 将 Day11
摘要上传为 day11-device-chain-evidence。Runtime quality gate 已包含本 E2E。
云端模块不得依赖 simulator，simulator 不得导入管理数据库工具或 API 实现。

此证据覆盖 LocalStack 和虚拟 ECU。真实 AWS IoT Core、车端固件、物理 CAN、
生产容量、HA/DR 仍需各自部署验收。


## Day11 复查与修复

| 优先级 | 已发现不足 | 本次修改 |
|---|---|---|
| P0 | 同一 SQLite 可被改配给另一车辆，旧命令可能误执行 | 绑定 tenant/vehicle；升级核对旧记录，不匹配拒绝启动 |
| P0 | 退避时跳过旧命令，可能让 UNLOCK 越过 LOCK | T-Box/Gateway 只选择最早未完成命令，增加双层顺序回归 |
| P1 | UDP 发送收到 peer unavailable 时退出进程 | 保留持久化 pending，处理连接拒绝/重置并继续重试 |
| P1 | HTTP 3xx 无限重试，base URL 可含凭据/query | 3xx 标 blocked，拒绝 URL userinfo/query/fragment，保持不跟随重定向 |
| P1 | ECU 测试继承 T-Box token/MQTT 配置 | Gateway/Body 只注入基本进程环境；身份仅注入 T-Box |
| P1 | broker 重启补投缺少证明 | E2E 使用磁盘 session，确认投递入 broker 后重启并恢复 |
| P1 | ACK ledger 查询缺少索引 | 增加 report command/sequence/state、pending 和 command state 索引 |

仍需后续验收或设计的缺口：

- P1：真实 AWS IoT Core、设备证书、物理 CAN；当前测试使用 localhost UDP 仿真。
- P1：云端多 publisher 的每车顺序协议。设备端 FIFO 只保证接收后的重试顺序；需要
  云端权威 sequence/version 与消费者兼容迁移，才能约束跨实例并发下发顺序。
- P1：账本归档、指标/告警与自动 token 刷新；已有积压上限、空间预留和分页，仍保留全部去重证据，
  token 由外部身份提供方轮换，不能凭测试数据随意删除账本。
- P1：broker 突然断电、磁盘损坏、重建后的恢复。此轮新增的是有序重启验收。
- 已修复：CAN expiry 毫秒格式及旧持久化命令帧兼容迁移，见下方升级说明。
- 当前修改仍需针对提交 SHA 获得远端 CI；本地绿色不等于 main 验收通过。

T-Box SQLite 首次绑定车辆/租户，旧账本升级时逐条核对。车辆变更必须使用新的独立目录；不能通过修改环境变量复用旧账本。


## 第二轮复查：背压、分页、重试与凭据输出

- DEVICE_MAX_PENDING_COMMANDS（默认 1000）限制未完成或尚未回报完的命令数。
  包括 terminal 但报告 pending/blocked 的命令，不能仅因 ECU 已执行就释放容量。
  已接收的相同命令可继续去重确认，不消耗新容量；新命令超限时不写 ACK outbox、
  不发送 MQTT PUBACK，断开后每 5 秒重试，HTTP reporter 与 CAN dispatcher 继续排空。
- DEVICE_MAX_QUARANTINE_RECORDS（默认 1000）限制不同坏消息摘要的数量；已有摘要仍可确认。
  达上限后保留原证据并对新消息背压，不循环删除审计记录。
- DEVICE_MIN_FREE_BYTES（默认 32 MiB）要求接收新命令/隔离新消息前留有磁盘空间。
  预留空间用于已接受命令的执行结果和回报更新。检查无法防止外部进程同时填满磁盘，
  SQLite 真实 I/O/磁盘写满错误仍会安全停止，未提交消息不 ACK；运维修复后重启恢复。
- HTTP/CAN 重试加入有界 jitter；HTTP 408/429/5xx 遵守 Retry-After 秒数或 HTTP 日期，
  最长自动等待 86400 秒，超过上限阻断，退避时间存入 SQLite。无效 header 忽略。不是立即重试或重新生成 event_id。
- 三份账本的 inspect/reconcile 默认最多返回各 1000 条，支持 --limit 1..1000、
  --offset 非负数，并返回总数。每次检查使用 SQLite 一致读快照；不同设备进程的
  检查仍是独立快照，跨账本核对应保留时间和 command_id/event_id。
- MQTT 密码使用 SecretStr，配置验证异常隐藏输入值。token 文件读取限制为 8 KiB、
  ASCII 单行，损坏/超长文件保留报告重试；不把 token 放入日志。

```powershell
.\.venv\Scripts\python.exe -m simulators.vehicle_device `
  --reconcile .device/tbox.sqlite --limit 100 --offset 100
.\.venv\Scripts\python.exe -m simulators.gateway `
  --database .device/gateway.sqlite --inspect --limit 100 --offset 100
.\.venv\Scripts\python.exe -m simulators.body_ecu `
  --database .device/body.sqlite --inspect --limit 100 --offset 100
```

背压会把积压保留在 broker，必须同步配置 broker 持久队列的容量/过期策略并监控磁盘。
修复 API/token、腾出安全磁盘空间后观察 pending 自动排空；禁止删去去重账本来腾空间。
已完成历史仍保留，归档/删除需要明确的命令重放窗口和版本化设计。本轮没有自动删除功能。

E2E 把待回报上限设置为 1，模拟 HTTP 中断，确认下一条命令没有写入设备数据库；恢复后
从 MQTT 重投并回报成功/失败。摘要记录 capacity_backpressure_recovered=true。


### 后续审计：CAN 到期精度与升级兼容

已修复整秒截断导致命令提前过期的问题。新增命令使用 7 字节帧：1 字节 opcode + 6 字节 UTC 毫秒时间戳；到期时间向上取整到毫秒，最多延后不足 1 毫秒。Gateway 和 Body ECU 同时接受旧 5 字节与新 7 字节命令帧。

T-Box SQLite 自动增加 can_version 列。升级前已持久化的命令固定为版本 1，重试仍发送原来的 5 字节内容；新接收的命令固定为版本 2。这样不会因升级改变同一 command_id 的内容而触发 ECU 冲突。部署时先升级 Gateway / Body ECU，再升级 T-Box；旧 ECU 不支持新帧，因此 T-Box 升级后不可单独回退 ECU。

新增回归覆盖小数秒有效期、精确到期边界、执行结果缓存、旧账本迁移和再次重启。Virtual CAN 初始化失败时也会关闭已创建的 socket。


本轮验证：538 项测试通过，包含独立进程 E2E 和数据库权限集成检查；ruff、格式检查、mypy 在排除 tests/unit/simulators/test_result_reporter.py 后通过。该现有文件引用不存在的 execution_store / result_reporter 模块，导致全量测试收集及 mypy 失败，并有格式错误；本轮保留该文件，未宣称全量检查绿色。Terraform fmt 与 local/dev validate 通过。


### 后续审计：上报回执与启动资源

遗留 test_result_reporter.py 已改为测试实际 Store / report_once 接口，不再引用不存在的模块，不再从质量检查中排除。保留重启后相同 event_id 重试、重定向持久阻断和缺失 Token 不发送等场景；401/403 仍按现有 Token 轮换契约进行有界退避重试，已有测试覆盖。

上报 HTTP 2xx 必须包含匹配的 command_id 和 acknowledged / succeeded / failed 状态。ACK 重试时云端可能已经终态，因此允许返回终态，不要求回执状态与事件状态完全相同。无效回执保留原事件并进入 blocked，记录 HTTP_INVALID_RECEIPT 与 device_report_invalid_receipt 日志，修复后可通过 --requeue-blocked 重放，不能把空响应或错误 command_id 当成云端已持久化。

Body ECU 绑定失败会关闭 SQLite；Gateway 第二个总线绑定失败也会关闭第一个总线与 SQLite。两个 CLI 在创建账本前验证端口范围 1..65535 与端口互异，避免错误配置创建无用账本。

仍待真实环境验收：AWS IoT Core / 物理 CAN、云端跨 publisher 每车顺序、账本归档与告警、自动身份刷新、broker 突然断电与灾难恢复，以及提交 SHA 对应的远端 CI / main 分支保护。这些不等同于本地模拟测试已证明。

本轮验证：553 项测试全部通过（无排除文件），包含 unit、contract、独立进程 E2E、数据库运行时权限集成检查；ruff check、ruff format --check（279 文件）、mypy（272 文件）、模块契约、Terraform fmt 与 local/dev validate、git diff --check 均通过。尚未验证远端 CI / 分支保护。


### 后续审计：重试截止时间、终态回执与运维数据

- 修复 Retry-After 截断：支持 408、429、所有 5xx 的秒数 / HTTP 日期等待，24 小时内完整持久化；超限记录 HTTP_RETRY_AFTER_TOO_LONG 并 blocked，不能提前重试。巨大的数字 header 也会阻断，不依赖无限精度整数转换。
- 修复上限处 jitter 消失：先限定指数基数再随机化，T-Box 与 Gateway 到达上限后仍使用不同等待时间。
- 终态 succeeded / failed 上报必须收到相同终态回执，否则保留原事件并阻断。ACK 上报仍允许云端已经进入终态。HTTP_REDIRECT_BLOCKED / HTTP_INVALID_RECEIPT 使用明确错误码，不伪装成服务端 422。
- result_commit 故障注入也覆盖设备本地判断的未支持命令与首次过期命令，不仅覆盖 CAN 响应。
- --reconcile 新增 health：全部账本的 command_states、report_states、report_attempts、最早未送达事件时间、SQLite 分配页字节数及磁盘可用空间。这些统计与分页无关；页字节数不是含 WAL 的文件总量，也不是自动告警部署。输出不包含 Token 或原始 HTTP 响应。归档、告警阈值和部署仍待实现。

工作区另外存在 DeviceExecutionStore / DeviceResultReporter 独立组件；该组件的响应 Protocol 改为只读属性，并消除指数计算的 Any 类型，使不可变响应测试对象也满足类型契约。它尚未接入当前六进程主链路，不能把它的额外能力当作主链路已部署能力。

本轮验证：606 项测试通过（无排除文件），包括 unit / contract / 两条独立进程 E2E / 数据库权限集成检查；ruff、format（283 文件）、mypy（275 文件）、模块契约、Terraform fmt 与 local/dev validate 通过。最后的对账字段调整后，设备及上报器测试另复查 120 项通过。远端 CI、分支保护及真实 AWS/物理 CAN 未在本轮验证。


### 后续审计：账本独占与安全重放

此前“每份 SQLite 一个进程”仅是操作要求，现在 T-Box、Gateway、Body ECU 启动前均取得数据库绝对路径对应的 .runtime.lock 操作系统非阻塞锁。第二个进程即使使用不同 CAN 端口，也会在打开账本前失败，记录 device_ledger_already_owned。锁由 Windows msvcrt / Linux flock 管理，正常退出、强制结束、崩溃都会释放；无需清理陈旧 PID。

运行中允许 --reconcile / --inspect 查看快照；--requeue-blocked 必须先停 T-Box，取得同一维护锁后才重放。关闭运行进程、修复阻断原因、执行重放、再启动进程；原 event_id / body 不变。锁文件需保留，不能在运行期间删除，否则可能形成两个锁对象。各进程使用同一规范化本地路径；硬链接别名、跨主机共享目录 / NFS 锁语义未验收，不属于当前部署契约。锁不限制单独调用 Store 的应用代码，新增入口必须使用 runtime_lock。

新增测试覆盖同账本第二个持有者、不同账本并行、真实子进程被强制结束后的重新取得锁、在线查看 / 离线重放，以及三个运行入口启动前拒绝重复拥有者。现有四个崩溃点 E2E 同时验证加入锁后仍能恢复。

独立 DeviceResultReporter 也补齐终态匹配与 Token 安全边界：空、非 ASCII、含 CR/LF、超 8192 字符 Token 不进入 HTTP 请求；Token supplier 的文件 / 值错误会持久退避，保持原事件。该独立组件仍未接入六进程 CLI。

之前的不足仍未全部完成：云端多 publisher 每车顺序、账本归档与自动告警、身份自动刷新、真实 AWS IoT / 物理 CAN、突然断电与灾难恢复、远端 CI SHA 验收和 main 强制分支保护，均不能由这些本地回归替代。

本轮验收：619 项测试全部通过，无排除文件（包含独立进程 E2E 与数据库权限集成）；ruff check、format（285 文件）、mypy（277 文件）、模块契约、Terraform fmt / local validate / dev validate、git diff --check 通过。远端 CI 与真实环境尚未验证。


### 后续审计：设备账本备份与恢复工具

新增 `python -m simulators.vehicle_device.maintenance --source SOURCE --destination NEW_FILE`，支持 T-Box、Gateway、Body ECU 及独立 DeviceExecutionStore 账本。使用 SQLite 在线 backup API 包含 WAL 中已提交数据；执行 integrity_check 后，刷新文件并以同目录硬链接原子发布，目标已存在时拒绝覆盖。失败 / 复制超时不会发布最终文件，临时文件会清理。目标需要支持本地硬链接（Windows NTFS / Linux 本地文件系统）；没有降级为非原子复制。

单文件在线备份可在对应进程运行时进行，源以 mode=ro 打开，目标取得独占维护锁。工具不读取 Token，也不输出事件正文。

Windows 示例（先在项目根目录运行）：

```powershell
.\.venv\Scripts\python.exe -m simulators.vehicle_device.maintenance --source runtime/day11/tbox/tbox.db --destination .device/backups/tbox-001.sqlite
```

SOURCE 应替换为当前进程配置的真实账本路径。恢复使用同一个命令，将快照作为 source，新的独立路径作为 destination；恢复后先通过 --reconcile / --inspect 核对状态与设备身份，再将对应 runtime 指向新路径。工具从不覆盖运行中的数据库，也不会替用户改运行配置。

三个进程的恢复需成组处理：停止 T-Box、Gateway、Body ECU，确认没有维护写入，再分别生成三个快照；恢复到三个新路径，核对关联命令和身份后一起启动。三个各自在线生成的快照不保证跨进程一致。单独回滚 Body ECU 到旧快照可能丢失更新的去重证据，不能据此重放未知执行结果；发现不一致必须先对账。SQLite integrity_check 仅证明数据库结构完整，不证明业务状态一致或真实 ECU 执行结果。

已覆盖：在线 WAL / ACK Outbox / 身份 / can_version 保留、恢复后相同命令不重复执行、Gateway 待转发命令恢复、现有文件保护、目标占用保护、未知账本拒绝与失败清理、复制超时，以及三类 Store 初始化失败时关闭连接。Windows 文件刷新使用可写句柄，兼容本机 fsync 行为。

此工具补齐本地账本快照与恢复基础，不代替异地备份、保留策略、加密存储、断电耐久性、RPO/RTO 及真实车辆恢复演练。归档和自动告警等之前的缺口仍未完成。

本轮验收：629 项测试通过，无排除文件（unit / contract / 独立进程 E2E / 数据库权限集成）。ruff、format（287 文件）、mypy（279 文件）、模块契约、Terraform fmt 和 local/dev validate、git diff --check 均通过。远端 CI 与真实环境仍未验证。


### 后续审计：按事件重放与 ACK 顺序

移除未经审计的全量重放：--requeue-blocked 现在必须同时提供 --event-id、--operation-id、--actor、--reason。两个 ID 必须为 UUID；操作者 / 原因不能为空或包含控制字符。只重放选中的 blocked 事件，不改变其他事件；pending / delivered / 未知事件不能重放。离线独占锁要求仍有效。

SQLite 新增 report_replays 审计表，将原错误、操作者、原因和时间与状态修改放在同一事务中。相同 operation_id 和相同参数重复执行不再次更新；同一 operation_id 变更事件 / 操作者 / 原因则冲突。审计记录通过 --reconcile 的 replay_audit 分页查看，也包含在 SQLite 快照中。该 actor 是本地操作声明，不替代生产级身份认证；CLI 访问仍依赖主机权限。不会保存 Token。

独立 DeviceExecutionStore 的 lease_reports 补齐 ACK 门禁：未送达或 blocked 的 ACK 会阻止同命令终态报告领取，包括租约过期后的重新领取；其他命令不被一起阻断。该独立组件仍未接入六进程入口。

Windows 强制结束后的 OS 锁句柄可能稍后才释放，三个运行入口允许最多 1 秒的非阻塞锁重试；等待期间不打开账本，未取得锁仍失败。维护入口仍立即拒绝占用。只有锁竞争错误映射为 device_ledger_already_owned，其他 I/O 错误不伪装成重复进程。

仍待完成的历史缺口：成组恢复工具、归档与自动告警、云端跨发布者车辆顺序、身份自动刷新、真实 AWS / 物理 CAN、断电 / 灾难恢复演练、远端 CI 与 main 分支保护验证。

本轮验收：636 项测试全部通过，无排除文件（unit / contract / 独立进程 E2E / 数据库权限集成）。ruff check / format（288 文件）、mypy（280 文件）、模块契约、Terraform fmt / local validate / dev validate、git diff --check 通过。首次完整检查发现的测试时钟相互影响已隔离，重新完整执行通过；未验证远端 CI 或真实环境。


Replay now requires --tenant-id and --vehicle-id matching the persisted device identity, including duplicate operations. See [the 12 acceptance checks](REPLAY_ACCEPTANCE.md).
