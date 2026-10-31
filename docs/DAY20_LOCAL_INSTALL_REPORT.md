# Day20 本机安装记录 — 2026-10-20

项目：`D:\project\ConnectedVehicle-AIoT-Enterprise`
分支：`wip/day20-infra-20261018`，原始 HEAD：`41a811b6f8489274ecbbdb1a874156d119dc7645`。
安装前工作区干净；安装包基线为更早的 `fc903383`。安装器所谓“未知本地修改”包含后来已提交的加固内容，并非只有未提交编辑。

## 安装与合并

- 校验 SHA256SUMS 中全部 23 个文件通过。审查安装器：仅复制限定后缀及目录，拒绝偏离旧基线的文件，拟移除旧 version.tf；无 AWS、Apply、推送或合并命令。因项目更新，采用逐文件审查合并，没有强制运行覆盖。
- 全部被涉及的既有文件已备份到 `C:\Users\admin\Downloads\Day20_install_backup_20261020_201755`，含 audit.json、merge-actions.json、差异及执行日志。原安装包未改动。
- 原 Bootstrap 与其他模块 contracts.tftest.hcl 的全部 run 保留。新增包内测试独立存于 day20_overlay.tftest.hcl。
- 保留较新治理代码的 manage_ou、OU 身份检查、退役操作 ID、retired_environments、资源保护条件和 Provider 6.x 的 policy_types[].type；未引入包内错误的 .name 或较弱的替代实现。
- 合并 offline/topology/OU 默认值；既有加固测试显式使用 enforce。固件删除保护扩展到专用固件桶全部对象，以覆盖 Day17 键布局；State 桶保持隔离。保留原 Sid，增加可审计输出。
- 合并精确对象键验证及 SSE 规则：允许默认桶加密，拒绝显式错误的 SSE/KMS 覆盖。保留现有 Secrets versions.tf 的版本约束，旧 version.tf 原本已不存在。
- 修正包内测试的 S3 rule 集合下标错误，使用 one(rule)；修正 Python 测试将完整项目误当增量包的 Bootstrap 文件断言，并兼容现有代码格式及 Provider 字段。

## 验证

| 范围 | init（禁用 backend） | validate | mock test |
|---|---|---|---|
| ota-governance | PASS | PASS | 32 passed |
| ota-artifact-bucket | PASS | PASS | 5 passed |
| ota-artifact-policy | PASS | PASS | 9 passed |
| ota-runtime-iam | PASS | PASS | 7 passed |
| ota-secrets | PASS | PASS | 7 passed |
| state-backend | PASS | PASS | 3 passed |

- 完整 `pytest tests/unit -q`：**1081 passed，118.76 秒**。首次运行在后来修复的文本检查处失败（1080 passed）；最终重跑全部通过。
- Day20 + IaC 定向检查：111 passed。
- 新增 Python 文件 Ruff check / format check：通过。
- 六个目标目录 fmt：通过；整个 Terraform 目录 fmt -check -recursive：通过。六组合计 63 项原生 mock 测试全部通过。
- git diff --check：通过，仅出现 Git 行尾规范提示。全部改动保持未提交，未 stage。最终 status 另存备份目录。

## 安全边界与待办

未执行真实 AWS Apply/Destroy、未推送、未 Git 合并、未创建提交。所有原生测试使用 mock AWS Provider；原有 Secrets 测试含一次模拟 apply（非真实 AWS 资源操作），其余为 plan。init 仅初始化依赖并禁用 backend。

尚未执行完整 IaC/Runtime CI、Checkov、Docker/LocalStack 部署、真实 AWS 授权与 SCP 验证。Campaign 独立数据库身份等原有边界仍需后续处理。不能将本次本机通过等同于生产验收。

Bootstrap 新增测试在执行期间于 20:23:53 被改写为 145 字节的不完整 HCL，已另存 bootstrap-concurrent-edit.tftest.hcl；用户确认没有编辑并授权从安装包恢复；已恢复并通过 init/validate/test。原 Bootstrap contracts.tftest.hcl 字节内容与备份完全一致。
