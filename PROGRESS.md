# 进度

会话之间唯一的状态载体。格式与规则见 `AGENTS.md` §3。

**新会话必须先逐条执行下表的验证命令，再决定做什么。** 本文件是待验证的声明，不是事实。

状态取值：`未开始` / `进行中` / `已完成` / `阻塞`

> 跑测试前需要一个 PostgreSQL 测试库并设置 `SUMMER_DB_TEST`，见 `db/README.md`。
> 未设置时集成测试会**失败**而不是跳过——没有数据库时报绿比测试失败更危险。

---

## 任务

| 任务 | 状态 | 验证命令 | 分支 |
|---|---|---|---|
| 文档基线 v3.0：卷间独立性与合卷残留修复 | 已完成 | `python3 tools/check_docs.py` | main |
| 文档基线 v3.0：全卷章节层级编号 | 已完成 | `python3 tools/check_docs.py` | main |
| 文档机检工具 | 已完成 | `python3 tools/check_docs.py` | main |
| AI 作业规范与作业机检 | 已完成 | `python3 tools/check_agents.py` | main |
| .NET 10 工具链 | 已完成 | `dotnet --version` | claude/project-development-vo5bng |
| solution 骨架与模块边界（16 模块 + 4 API + Worker） | 已完成 | `dotnet build Summer.slnx` | claude/project-development-vo5bng |
| BuildingBlocks 公共构件 | 已完成 | `dotnet test tests/Summer.Tests.Unit/Summer.Tests.Unit.csproj` | claude/project-development-vo5bng |
| iam schema 迁移（user_account / user_session / session_refresh_token） | 已完成 | `dotnet test tests/Summer.Tests.Integration/Summer.Tests.Integration.csproj` | claude/project-development-vo5bng |
| Identity 登录会话纵切（登录 / 刷新轮换 / 重放处置 / 登出） | 已完成 | `dotnet test tests/Summer.Tests.Integration/Summer.Tests.Integration.csproj --filter FullyQualifiedName~SessionStateMachineTests` | claude/project-development-vo5bng |
| audit_event 哈希链（DOM-PUB-001 部分） | 已完成 | `dotnet test tests/Summer.Tests.Integration/Summer.Tests.Integration.csproj --filter FullyQualifiedName~AuditChainTests` | claude/project-development-vo5bng |
| Platform.Api 会话端点 | 已完成 | `dotnet build src/Apis/Summer.Platform.Api` | claude/project-development-vo5bng |
| CI：编译 / 格式 / 测试 / 迁移重放 / 依赖安全 | 已完成 | `dotnet build Summer.slnx && dotnet format Summer.slnx --verify-no-changes` | claude/project-development-vo5bng |
| MFA 与身份挑战（user_mfa_factor / auth_challenge） | 未开始 | — | — |
| Organization / LegalEntity 实体与迁移 | 未开始 | — | — |
| Workspace 协作模型实体与迁移 | 未开始 | — | — |
| Authorization：角色、权限、作用域与 SoD | 未开始 | — | — |
| 权限种子导入工具 | 未开始 | — | — |
| PROVIDER / ENTERPRISE 会话与 Workspace 上下文 | 阻塞 | — | — |
| Outbox 与后台任务（DOM-PUB-001 其余部分） | 未开始 | — | — |
| 覆盖率门槛与报告 | 未开始 | — | — |

---

## 串行专属文件占用

改动 `AGENTS.md` §4 串行专属清单中的文件前，在此登记；完成后立即删除该行。

| 文件 | 占用分支 | 登记时间 |
|---|---|---|
| （当前无占用） | — | — |

---

## 阻塞与待决

| 事项 | 阻塞原因 | 需谁决定 |
|---|---|---|
| `DEC-IAM-001` 会话寿命、MFA、重新认证与设备策略 | 未冻结。实现已按 `AGENTS.md` §7 拒绝填默认值：`SessionPolicy` 四项数值必须由环境变量显式提供，缺失即启动失败 | OWNER + 安全，`GATE-LLD` |
| access token 的最终形态 | 字段字典 §5.2.4 未给 access token 摘要列。自包含签名令牌需密钥服务，而密钥服务属 §4.11 待冻结第 6 项。当前只交付 refresh token 与服务端会话校验 | OWNER + 安全 |
| 跨模块接口 `IOrganizationContextVerifier` | Identity 新增的对 DOM-ORG-001 只读查询契约，尚未与该模块负责方确认（`AGENTS.md` §4）。未实现前 PROVIDER/ENTERPRISE 会话失败关闭 | DOM-ORG-001 负责方 |
| §8.10 错误码目录补充 3 条 | `AUTH-CREDENTIAL-001` / `AUTH-REFRESH-001` / `AUTH-SESSION-001`，均在冻结前缀下新增，登记于 `ErrorCodes.Introduced` | OWNER（治理） |
| 数据访问方式（当前手写 SQL + Npgsql，未引入 ORM） | 已冻结基线只到 PostgreSQL；ORM 属新外部依赖，按 `AGENTS.md` §7 需决定后引入。手写 SQL 在 16 个模块规模上的可维护性需评估 | OWNER + 架构 |
| §5.20 迁移质量门第 2–6 项 | 已交付第 1 项中 iam/audit 两个 schema 的 DDL；RLS 策略与穿透测试、历史映射、EXPLAIN 基线、密文迁移与密钥轮换方案、全量一致性校验均未做 | OWNER，`GATE-LLD` |
| `audit_partition_anchor` 分区封存与签名 | 依赖密钥服务（§4.11 第 6 项）。当前 `hash_key_version=0` 表示无密钥 SHA-256 链 | OWNER + 安全 |
| 幂等键去重存储 | 命令已强制携带 `Idempotency-Key` 并记入审计，但「同键异摘要返回 `DUP-IDEMPOTENCY-002`」的去重事实属 DOM-PUB-001，尚未实现 | —（随 DOM-PUB-001 交付） |
| 连接器（税局、银行、电子签） | 供应商未选定，POC 未做 | OWNER |
| 税务地区与表单覆盖 | `DEC-TAX-001` 未冻结 | OWNER + TAX-ADVISOR |
| 容量与性能指标 | `DEC-CAP-001` 未冻结，`NFR-PERF-001` 的 P95 目标无验证基准 | OWNER |
| 需求追踪制品 | 手册 §2 第 6 条将需求—设计—测试映射交给仓库制品，尚未建立；149 条 FR 目前无一被下游引用 | OWNER 定优先级 |

---

## 下一个建议纵切

Identity 已打通 PLATFORM 受众的完整会话链路。下一步按依赖顺序：

1. **Organization + LegalEntity**（`DOM-ORG-001`）——`STATE-ORG-001` 状态机、能力 request/approve、成员邀请与接受；
2. 实现 `IOrganizationContextVerifier`，接通 PROVIDER / ENTERPRISE 会话；
3. **Workspace**（`DOM-WSP-001`）——双主参与方约束、`workspace_session_context`。

第 1 步不依赖任何未冻结决策，可直接开工；第 2 步是第 1 步的自然出口；
第 3 步的 `PARTNER` 参与方首期禁用（§4.2.2），不要实现。
