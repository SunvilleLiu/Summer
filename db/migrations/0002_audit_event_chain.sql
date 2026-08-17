-- =============================================================================
-- audit schema：只追加的审计事件哈希链
--
-- 依据：docs/04-系统设计.md
--   §4.7.1  逻辑模式划分（audit）
--   §5.6.3  audit_event 必备字段与链约束
--   §3.1 §3 每次状态迁移只追加事件
--   §5.19  审计不得物理删除
--
-- 交付边界：
--   本脚本交付链本体（chain_sequence / previous_event_hash / event_hash）。
--   `audit_partition_anchor` 的**分区封存与 KMS 签名未交付**：签名依赖密钥服务，
--   而密钥服务属 §4.11 待冻结第 6 项。因此 hash_key_version 恒为 0，
--   表示当前使用无密钥 SHA-256；引入 keyed hash 时以新版本号并行写入，不改写历史。
-- =============================================================================

create schema if not exists audit;

-- -----------------------------------------------------------------------------
-- audit_chain —— 每条链的游标
-- §5.6.3 要求「同一链追加通过数据库锁/受控序列串行化」。
-- 把游标单独成行，追加时 select ... for update 该行即可串行化，
-- 比在 audit_event 上取 max(chain_sequence) 更可靠：后者在并发下会读到同一最大值。
-- -----------------------------------------------------------------------------
create table audit.audit_chain (
    chain_scope_type  varchar(30) not null,
    chain_scope_id    uuid        not null,
    current_sequence  bigint      not null default 0,
    last_event_hash   char(64)        null,
    created_at        timestamptz not null,
    updated_at        timestamptz not null,

    constraint pk_audit_chain primary key (chain_scope_type, chain_scope_id),
    constraint ck_audit_chain_scope_type
        check (chain_scope_type in ('PLATFORM', 'ORGANIZATION', 'WORKSPACE')),
    constraint ck_audit_chain_sequence_non_negative check (current_sequence >= 0)
);

comment on table audit.audit_chain is '审计链游标，使 chain_sequence 的追加可被行锁串行化';


-- -----------------------------------------------------------------------------
-- audit_event (ENT-PUB-001) —— 只追加
-- -----------------------------------------------------------------------------
create table audit.audit_event (
    id                    uuid         not null,

    -- §5.6.3：均使用 scope_type/scope_id
    scope_type            varchar(30)  not null,
    scope_id              uuid             null,

    -- §1.8.3：事件必须显式声明 Audience 与 scope，且不伪造 organizationId/workspaceId
    audience              varchar(20)      null,
    organization_id       uuid             null,
    workspace_id          uuid             null,
    legal_entity_id       uuid             null,
    accounting_book_id    uuid             null,

    object_type           varchar(60)      null,
    object_id             uuid             null,
    from_status           varchar(30)      null,
    to_status             varchar(30)      null,

    event_type            varchar(100) not null,
    event_version         integer      not null default 1,
    reason_code           varchar(50)      null,
    idempotency_key       varchar(100)     null,
    correlation_id        varchar(100)     null,
    actor_account_id      uuid             null,
    risk_level            varchar(20)  not null default 'NORMAL',

    -- 非敏感摘要。§6：日志与审计不得出现令牌、密钥或 L4 明文
    summary               varchar(1000)    null,

    occurred_at           timestamptz  not null,

    -- §5.6.3 链字段
    chain_scope_type      varchar(30)  not null,
    chain_scope_id        uuid         not null,
    chain_sequence        bigint       not null,
    previous_event_hash   char(64)         null,
    event_hash            char(64)     not null,
    hash_algorithm        varchar(30)  not null,
    hash_key_version      integer      not null,

    partition_key         char(6)      not null,
    partition_anchor_id   uuid             null,

    created_at            timestamptz  not null,
    created_by            uuid             null,

    constraint pk_audit_event primary key (id),

    -- §5.6.3：链内序号唯一，缺号与重排都能被检出
    constraint uq_audit_event_chain
        unique (chain_scope_type, chain_scope_id, chain_sequence),

    constraint fk_audit_event_chain
        foreign key (chain_scope_type, chain_scope_id)
        references audit.audit_chain (chain_scope_type, chain_scope_id),

    constraint ck_audit_event_scope_type
        check (scope_type in ('PLATFORM', 'ORGANIZATION', 'WORKSPACE', 'LEGAL_ENTITY', 'BOOK', 'OBJECT')),
    constraint ck_audit_event_audience
        check (audience is null or audience in ('PLATFORM', 'PROVIDER', 'ENTERPRISE')),
    constraint ck_audit_event_risk
        check (risk_level in ('NORMAL', 'HIGH')),
    constraint ck_audit_event_sequence_positive check (chain_sequence >= 1),

    -- §1.8.3：PLATFORM 事件不伪造 organizationId/workspaceId
    constraint ck_audit_event_platform_scope check (
        audience is distinct from 'PLATFORM'
        or (organization_id is null and workspace_id is null)
    ),

    -- 链首无前序；非链首必须有前序。缺这条约束，断链会静默通过
    constraint ck_audit_event_chain_head check (
        (chain_sequence = 1 and previous_event_hash is null)
        or (chain_sequence > 1 and previous_event_hash is not null)
    )
);

create index ix_audit_event_occurred on audit.audit_event (occurred_at);
create index ix_audit_event_object on audit.audit_event (object_type, object_id);
create index ix_audit_event_actor on audit.audit_event (actor_account_id, occurred_at);

-- 高风险事件要能被告警侧快速扫描（§6 安全监测）
create index ix_audit_event_high_risk
    on audit.audit_event (occurred_at) where risk_level = 'HIGH';

comment on table audit.audit_event is
    'ENT-PUB-001 只追加审计事件，含防篡改哈希链，见 docs/04-系统设计.md §5.6.3';
comment on column audit.audit_event.hash_key_version is
    '0 表示无密钥 SHA-256；keyed hash 待密钥服务冻结（§4.11 第 6 项）后以新版本号引入';
comment on column audit.audit_event.partition_anchor_id is
    '分区锚点，随 audit_partition_anchor 的封存与签名一并交付，当前恒为 null';


-- -----------------------------------------------------------------------------
-- §5.19：审计不得物理删除。用规则在数据库层挡住 delete/update，
-- 应用层的自觉不足以保护审计链——绕过应用层的直连同样必须被拒绝。
-- -----------------------------------------------------------------------------
create rule audit_event_no_delete as on delete to audit.audit_event do instead nothing;
create rule audit_event_no_update as on update to audit.audit_event do instead nothing;
