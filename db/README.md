# 数据库迁移

`migrations/` 下是可执行的 PostgreSQL DDL，对应 `docs/04-系统设计.md` §5.20 第 1 项的交付物。

## 为什么是原生 SQL

§5.4.2、§5.3.5 等处要求的排他约束（`EXCLUDE USING gist`）、部分唯一索引和延迟约束
是 DDL 层的业务不变量，必须逐字可评审。由 ORM 生成的迁移做不到这一点。

数据访问方式尚未最终决定，见 `PROGRESS.md` 待决表。

## 约定

- 文件名 `NNNN_描述.sql`，序号零填充四位，**序号即执行顺序**；
- 每个脚本在独立事务内执行，并按内容摘要登记到 `platform.schema_migration`；
- **已应用的脚本不得改写**：摘要变化时 `MigrationRunner` 直接拒绝，需求变更请追加新脚本；
- 换行符差异（CRLF/LF）不计入摘要，跨平台检出不会误报。

## 已有脚本

| 脚本 | schema | 内容 |
|---|---|---|
| `0001_iam_identity_session.sql` | `iam` | `user_account` / `user_session` / `session_refresh_token` |
| `0002_audit_event_chain.sql` | `audit` | `audit_chain` / `audit_event`，只追加哈希链 |

## 本地执行

```bash
createdb summer_dev
export SUMMER_DB="Host=127.0.0.1;Port=5432;Database=summer_dev;Username=summer;Password=<pwd>"
for f in db/migrations/*.sql; do psql -d summer_dev -v ON_ERROR_STOP=1 -f "$f"; done
```

## 测试库

集成测试需要一个**专用**库——夹具在每轮开始时会清空其全部业务 schema：

```bash
createdb summer_test
export SUMMER_DB_TEST="Host=127.0.0.1;Port=5432;Database=summer_test;Username=summer;Password=<pwd>"
dotnet test tests/Summer.Tests.Integration/Summer.Tests.Integration.csproj
```

未设置 `SUMMER_DB_TEST` 时集成测试**失败**而不是跳过：
没有数据库时报绿，比测试失败更危险。

## 运行期环境变量

| 变量 | 用途 |
|---|---|
| `SUMMER_DB` | 应用连接串 |
| `SUMMER_DB_TEST` | 集成测试连接串 |
| `SUMMER_IAM_ACCESS_TOKEN_SECONDS` | 会话有效期，**属未冻结的 `DEC-IAM-001`** |
| `SUMMER_IAM_REFRESH_TOKEN_SECONDS` | refresh token 单代有效期，同上 |
| `SUMMER_IAM_MAX_FAILED_ATTEMPTS` | 触发锁定的连续失败次数，同上 |
| `SUMMER_IAM_LOCKOUT_SECONDS` | 锁定时长，同上 |

后四项没有默认值，缺失即启动失败。这是刻意的：`DEC-IAM-001` 在 `GATE-LLD` 冻结前，
任何默认值都等于替 OWNER 做决定（`AGENTS.md` §7）。
