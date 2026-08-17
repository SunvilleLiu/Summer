-- =============================================================================
-- iam schema：登录身份与会话
--
-- 依据：docs/04-系统设计.md
--   §4.7.1  逻辑模式划分（iam）
--   §5.1.2  通用列与作用域列
--   §5.2.2  user_account          (ENT-IAM-001)
--   §5.2.4  user_session / session_refresh_token (ENT-IAM-002)
--   §3.3.1  STATE-IAM-001 账号与会话状态机
--   §1.8.1  标识与外键约定（不使用无语义裸 tenant_id）
--
-- 交付边界：本脚本只覆盖 §5.20 第 1 项中 iam 三张表的 DDL 部分。
-- RLS 策略、EXPLAIN 基线、历史映射、密文迁移方案与全量一致性校验（§5.20 第 2-6 项）
-- 均未交付，GATE 未放行。
--
-- 未建表说明：user_mfa_factor / auth_challenge（§5.2.3）随 MFA 与密码重置纵切交付。
-- 建空表会让「有表即有实现」的假设成立，而实际无任何写入路径。
-- =============================================================================

create schema if not exists iam;

-- -----------------------------------------------------------------------------
-- user_account (ENT-IAM-001) —— 平台级登录身份
-- §7.2.1：账号本身不拥有业务数据，成员关系也不自动授予业务角色。
-- 因此本表没有 organization_id：账号不属于任何 Organization。
-- -----------------------------------------------------------------------------
create table iam.user_account (
    id                      uuid         not null,

    login_name_normalized   varchar(100) not null,
    mobile_cipher           text             null,
    mobile_hash             char(64)         null,
    email_cipher            text             null,
    email_hash              char(64)         null,
    password_hash           text         not null,

    -- 改密、停用、风险处置时递增；会话持有创建时的快照，不等即失效（§7.2.4 第 8 条）
    session_version         bigint       not null default 1,

    failed_count            integer      not null default 0,
    locked_until            timestamptz      null,
    last_login_at           timestamptz      null,
    password_changed_at     timestamptz      null,

    status                  varchar(20)  not null,

    created_at              timestamptz  not null,
    created_by              uuid         not null,
    updated_at              timestamptz  not null,
    updated_by              uuid         not null,
    row_version             bigint       not null default 1,

    constraint pk_user_account primary key (id),

    -- §5.2.2：平台内唯一
    constraint uq_user_account_login_name unique (login_name_normalized),

    -- §3.3.1 账号状态：ACTIVE → LOCKED/DISABLED
    constraint ck_user_account_status
        check (status in ('ACTIVE', 'LOCKED', 'DISABLED')),

    -- 密文与摘要成对出现：只有密文无摘要则无法检索，只有摘要无密文则无法还原
    constraint ck_user_account_mobile_pair
        check ((mobile_cipher is null) = (mobile_hash is null)),
    constraint ck_user_account_email_pair
        check ((email_cipher is null) = (email_hash is null)),

    constraint ck_user_account_session_version_positive check (session_version >= 1),
    constraint ck_user_account_failed_count_non_negative check (failed_count >= 0),
    constraint ck_user_account_row_version_positive check (row_version >= 1)
);

-- §5.2.2：手机/邮箱摘要非空时分别唯一。部分唯一索引使 NULL 不参与唯一性。
create unique index uq_user_account_mobile_hash
    on iam.user_account (mobile_hash) where mobile_hash is not null;
create unique index uq_user_account_email_hash
    on iam.user_account (email_hash) where email_hash is not null;

comment on table iam.user_account is 'ENT-IAM-001 平台级登录身份，见 docs/04-系统设计.md §5.2.2';
comment on column iam.user_account.session_version is '账号安全版本，改密/停用/风险处置时递增，使既有会话失效';


-- -----------------------------------------------------------------------------
-- user_session (ENT-IAM-002) —— 受众冻结的服务端会话
-- §4.2.3：一个会话只能冻结一种 Audience，切换受众必须新建会话。
-- §3.3.1：ACTIVE → EXPIRED/REVOKED，终态不可恢复。
-- -----------------------------------------------------------------------------
create table iam.user_session (
    id                        uuid         not null,

    session_no                varchar(100) not null,
    user_account_id           uuid         not null,
    audience                  varchar(20)  not null,

    -- §5.2.4：PROVIDER/ENTERPRISE 必填且属于该 organization/user；PLATFORM 必须为空。
    -- 约束由下方 ck_user_session_audience_scope 强制，不靠应用层自觉。
    organization_id           uuid             null,
    organization_member_id    uuid             null,

    session_version_snapshot  bigint       not null,
    refresh_family_id         uuid         not null,

    auth_strength             varchar(20)  not null,
    mfa_at                    timestamptz      null,

    started_at                timestamptz  not null,
    last_seen_at              timestamptz  not null,
    expires_at                timestamptz  not null,
    revoked_at                timestamptz      null,
    revoke_reason             varchar(500)     null,

    status                    varchar(20)  not null,

    created_at                timestamptz  not null,
    created_by                uuid         not null,
    updated_at                timestamptz  not null,
    updated_by                uuid         not null,
    row_version               bigint       not null default 1,

    constraint pk_user_session primary key (id),
    constraint uq_user_session_no unique (session_no),

    constraint fk_user_session_account
        foreign key (user_account_id) references iam.user_account (id),

    constraint ck_user_session_audience
        check (audience in ('PLATFORM', 'PROVIDER', 'ENTERPRISE')),

    -- §4.2.3 / §5.2.4：受众与 Organization 上下文的对应关系
    constraint ck_user_session_audience_scope check (
        (audience = 'PLATFORM'
             and organization_id is null
             and organization_member_id is null)
        or (audience in ('PROVIDER', 'ENTERPRISE')
             and organization_id is not null
             and organization_member_id is not null)
    ),

    -- §7.2.4 第 5 条
    constraint ck_user_session_auth_strength
        check (auth_strength in ('PASSWORD', 'MFA', 'REAUTH')),

    -- §3.3.1 会话状态：ACTIVE → EXPIRED/REVOKED
    constraint ck_user_session_status
        check (status in ('ACTIVE', 'EXPIRED', 'REVOKED')),

    -- 撤销必须留证据：状态与证据分离会让「谁撤的、为什么」永久丢失
    constraint ck_user_session_revoke_evidence check (
        (status = 'REVOKED' and revoked_at is not null and revoke_reason is not null)
        or (status <> 'REVOKED' and revoked_at is null and revoke_reason is null)
    ),

    constraint ck_user_session_lifecycle check (expires_at > started_at),
    constraint ck_user_session_row_version_positive check (row_version >= 1)
);

-- 撤销账号全部会话、按账号查活动会话：两者都以 (account, status) 为前缀
create index ix_user_session_account_status
    on iam.user_session (user_account_id, status);

-- 过期清理批处理按到期时间扫描 ACTIVE 行
create index ix_user_session_active_expiry
    on iam.user_session (expires_at) where status = 'ACTIVE';

comment on table iam.user_session is 'ENT-IAM-002 受众冻结的服务端会话，见 docs/04-系统设计.md §5.2.4';
comment on column iam.user_session.session_version_snapshot is '创建时的账号安全版本；与账号当前值不等即会话失效';


-- -----------------------------------------------------------------------------
-- session_refresh_token (ENT-IAM-002) —— family + 单次旋转
-- §5.2.4 / §6（安全）：服务端只存每代摘要；消费旧代与签发新代在同一事务；
-- 任何已消费代重用即撤销整个 family 与 session、递增账号 session_version。
-- -----------------------------------------------------------------------------
create table iam.session_refresh_token (
    id                    uuid         not null,

    session_id            uuid         not null,
    family_id             uuid         not null,
    generation            integer      not null,

    -- §7.2.4：只保存摘要，不明文落库
    token_hash            char(64)     not null,

    issued_at             timestamptz  not null,
    expires_at            timestamptz  not null,
    consumed_at           timestamptz      null,
    replaced_by_token_id  uuid             null,
    revoked_at            timestamptz      null,
    revoke_reason         varchar(500)     null,

    status                varchar(20)  not null,

    created_at            timestamptz  not null,
    created_by            uuid         not null,
    updated_at            timestamptz  not null,
    updated_by            uuid         not null,
    row_version           bigint       not null default 1,

    constraint pk_session_refresh_token primary key (id),

    -- §5.2.4：全局唯一 token_hash，且同一 family 的每一代只能有一行。
    -- 后者是「并发刷新不得产生分叉」的数据库级保证：两个并发请求都想创建
    -- generation N+1 时，唯一约束让其中一个失败，而不是产生两条有效链。
    constraint uq_session_refresh_token_hash unique (token_hash),
    constraint uq_session_refresh_token_generation unique (family_id, generation),

    constraint fk_session_refresh_token_session
        foreign key (session_id) references iam.user_session (id),
    constraint fk_session_refresh_token_replaced_by
        foreign key (replaced_by_token_id) references iam.session_refresh_token (id),

    constraint ck_session_refresh_token_status
        check (status in ('ACTIVE', 'CONSUMED', 'REVOKED', 'EXPIRED', 'REUSED')),

    constraint ck_session_refresh_token_generation_positive check (generation >= 1),

    -- CONSUMED 必须有消费时间与后继：缺任一项就无法证明旋转链完整
    constraint ck_session_refresh_token_consumed check (
        status <> 'CONSUMED'
        or (consumed_at is not null and replaced_by_token_id is not null)
    ),

    constraint ck_session_refresh_token_revoked check (
        status not in ('REVOKED', 'REUSED')
        or (revoked_at is not null and revoke_reason is not null)
    ),

    constraint ck_session_refresh_token_lifecycle check (expires_at > issued_at),
    constraint ck_session_refresh_token_row_version_positive check (row_version >= 1)
);

-- 重放检测要在整个 family 上撤销，按 family 定位全部代
create index ix_session_refresh_token_family
    on iam.session_refresh_token (family_id);

create index ix_session_refresh_token_session
    on iam.session_refresh_token (session_id);

comment on table iam.session_refresh_token is
    'ENT-IAM-002 refresh token family 单次旋转，见 docs/04-系统设计.md §5.2.4';
comment on column iam.session_refresh_token.status is
    'REUSED 表示已消费代被重放，触发整个 family 与 session 撤销';
