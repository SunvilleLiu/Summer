using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Npgsql;
using Summer.BuildingBlocks.Application;
using Summer.BuildingBlocks.Infrastructure;

namespace Summer.Modules.PublicCapabilities.Infrastructure;

/// <summary>
/// 把审计事实写入 <c>audit.audit_event</c> 并维护防篡改哈希链（§5.6.3）。
///
/// 链的串行化靠 <c>audit.audit_chain</c> 上的行锁：
/// 同一链的并发追加会在此排队，因此 chain_sequence 不会重号，
/// previous_event_hash 也不会指向被别人抢走的前序。
/// </summary>
public sealed class PostgresAuditSink : IAuditSink
{
    /// <summary>当前哈希算法。无密钥 SHA-256，对应 <c>hash_key_version = 0</c>。</summary>
    private const string HashAlgorithm = "SHA-256";

    /// <summary>
    /// 密钥版本 0 表示未使用 keyed hash。
    /// keyed hash 需要密钥服务，而密钥服务属 §4.11 待冻结第 6 项，
    /// 冻结后以新版本号并行写入，历史行的版本号不改写。
    /// </summary>
    private const int HashKeyVersion = 0;

    private const string PlatformChainScope = "PLATFORM";
    private const string OrganizationChainScope = "ORGANIZATION";

    /// <summary>
    /// 哈希输入的字段分隔符（ASCII unit separator）。
    /// 取一个业务数据里不可能出现的控制字符，使字段边界无法被内容伪造。
    /// </summary>
    private const char FieldSeparator = '\u001F';

    public async Task WriteAsync(
        AuditEntry entry,
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(transaction);

        (string chainScopeType, Guid chainScopeId) = ResolveChain(entry);

        (long sequence, string? previousHash) = await AdvanceChainAsync(
            connection, transaction, chainScopeType, chainScopeId, entry.OccurredAt, cancellationToken);

        Guid id = Guid.NewGuid();
        string eventHash = ComputeHash(entry, chainScopeType, chainScopeId, sequence, previousHash);

        await InsertEventAsync(
            connection, transaction, id, entry, chainScopeType, chainScopeId,
            sequence, previousHash, eventHash, cancellationToken);

        await CommitChainAsync(
            connection, transaction, chainScopeType, chainScopeId,
            sequence, eventHash, entry.OccurredAt, cancellationToken);
    }

    /// <summary>
    /// 选链。§1.8.3：PLATFORM 事件不得伪造 organizationId，
    /// 因此平台事件走独立的平台链，链标识用空 GUID 而非某个 Organization。
    /// </summary>
    private static (string ScopeType, Guid ScopeId) ResolveChain(AuditEntry entry)
        => entry.OrganizationId is { } organizationId
            ? (OrganizationChainScope, organizationId)
            : (PlatformChainScope, Guid.Empty);

    /// <summary>取链游标并加行锁；链不存在则先建。返回本次应使用的序号与前序哈希。</summary>
    private static async Task<(long Sequence, string? PreviousHash)> AdvanceChainAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction,
        string chainScopeType, Guid chainScopeId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        await using (NpgsqlCommand ensure = Command(connection, transaction, """
            insert into audit.audit_chain
                (chain_scope_type, chain_scope_id, current_sequence, created_at, updated_at)
            values (@scope_type, @scope_id, 0, @now, @now)
            on conflict (chain_scope_type, chain_scope_id) do nothing
            """))
        {
            ensure.Parameters.AddWithValue("scope_type", chainScopeType);
            ensure.Parameters.AddWithValue("scope_id", chainScopeId);
            ensure.Parameters.AddWithValue("now", now);
            await ensure.ExecuteNonQueryAsync(cancellationToken);
        }

        await using NpgsqlCommand cursor = Command(connection, transaction, """
            select current_sequence, last_event_hash from audit.audit_chain
            where chain_scope_type = @scope_type and chain_scope_id = @scope_id
            for update
            """);
        cursor.Parameters.AddWithValue("scope_type", chainScopeType);
        cursor.Parameters.AddWithValue("scope_id", chainScopeId);

        await using NpgsqlDataReader reader = await cursor.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            throw new InvalidOperationException($"审计链 {chainScopeType}/{chainScopeId} 不存在");
        }

        long current = reader.GetInt64(0);
        string? lastHash = reader.IsDBNull(1) ? null : reader.GetString(1);
        return (current + 1, lastHash);
    }

    /// <summary>
    /// 由不可变字段、前序哈希与链标识计算事件哈希（§5.6.3）。
    ///
    /// 字段之间用单元分隔符隔开而不是直接拼接：
    /// 否则 ("ab","c") 与 ("a","bc") 会算出同一个哈希，链就能被构造出碰撞。
    /// </summary>
    private static string ComputeHash(
        AuditEntry entry, string chainScopeType, Guid chainScopeId, long sequence, string? previousHash)
    {
        var builder = new StringBuilder();

        void Append(string? value)
        {
            builder.Append(value ?? string.Empty).Append(FieldSeparator);
        }

        Append(chainScopeType);
        Append(chainScopeId.ToString("D"));
        Append(sequence.ToString(CultureInfo.InvariantCulture));
        Append(previousHash);
        Append(entry.EventType);
        Append(entry.OccurredAt.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
        Append(entry.ActorAccountId?.ToString("D"));
        Append(entry.AudienceCode);
        Append(entry.OrganizationId?.ToString("D"));
        Append(entry.WorkspaceId?.ToString("D"));
        Append(entry.ObjectType);
        Append(entry.ObjectId?.ToString("D"));
        Append(entry.FromStatus);
        Append(entry.ToStatus);
        Append(entry.ReasonCode);
        Append(entry.IdempotencyKey);
        Append(entry.CorrelationId);
        Append(entry.Summary);
        Append(entry.Risk.ToString());

        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(builder.ToString())));
    }

    private static async Task InsertEventAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction, Guid id, AuditEntry entry,
        string chainScopeType, Guid chainScopeId, long sequence, string? previousHash, string eventHash,
        CancellationToken cancellationToken)
    {
        await using NpgsqlCommand command = Command(connection, transaction, """
            insert into audit.audit_event (
                id, scope_type, scope_id, audience, organization_id, workspace_id,
                object_type, object_id, from_status, to_status,
                event_type, event_version, reason_code, idempotency_key, correlation_id,
                actor_account_id, risk_level, summary, occurred_at,
                chain_scope_type, chain_scope_id, chain_sequence,
                previous_event_hash, event_hash, hash_algorithm, hash_key_version,
                partition_key, created_at, created_by)
            values (
                @id, @scope_type, @scope_id, @audience, @organization_id, @workspace_id,
                @object_type, @object_id, @from_status, @to_status,
                @event_type, 1, @reason_code, @idempotency_key, @correlation_id,
                @actor_account_id, @risk_level, @summary, @occurred_at,
                @chain_scope_type, @chain_scope_id, @chain_sequence,
                @previous_event_hash, @event_hash, @hash_algorithm, @hash_key_version,
                @partition_key, @occurred_at, @actor_account_id)
            """);

        command.Parameters.AddWithValue("id", id);
        command.Parameters.AddWithValue("scope_type",
            entry.WorkspaceId is not null ? "WORKSPACE"
            : entry.OrganizationId is not null ? "ORGANIZATION"
            : "PLATFORM");
        AddNullable(command, "scope_id", entry.WorkspaceId ?? entry.OrganizationId);
        AddNullable(command, "audience", entry.AudienceCode);
        AddNullable(command, "organization_id", entry.OrganizationId);
        AddNullable(command, "workspace_id", entry.WorkspaceId);
        AddNullable(command, "object_type", entry.ObjectType);
        AddNullable(command, "object_id", entry.ObjectId);
        AddNullable(command, "from_status", entry.FromStatus);
        AddNullable(command, "to_status", entry.ToStatus);
        command.Parameters.AddWithValue("event_type", entry.EventType);
        AddNullable(command, "reason_code", entry.ReasonCode);
        AddNullable(command, "idempotency_key", entry.IdempotencyKey);
        AddNullable(command, "correlation_id", entry.CorrelationId);
        AddNullable(command, "actor_account_id", entry.ActorAccountId);
        command.Parameters.AddWithValue("risk_level", entry.Risk == AuditRisk.High ? "HIGH" : "NORMAL");
        AddNullable(command, "summary", entry.Summary);
        command.Parameters.AddWithValue("occurred_at", entry.OccurredAt);
        command.Parameters.AddWithValue("chain_scope_type", chainScopeType);
        command.Parameters.AddWithValue("chain_scope_id", chainScopeId);
        command.Parameters.AddWithValue("chain_sequence", sequence);
        AddNullable(command, "previous_event_hash", previousHash);
        command.Parameters.AddWithValue("event_hash", eventHash);
        command.Parameters.AddWithValue("hash_algorithm", HashAlgorithm);
        command.Parameters.AddWithValue("hash_key_version", HashKeyVersion);
        command.Parameters.AddWithValue("partition_key",
            entry.OccurredAt.ToUniversalTime().ToString("yyyyMM", CultureInfo.InvariantCulture));

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task CommitChainAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction,
        string chainScopeType, Guid chainScopeId, long sequence, string eventHash, DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        await using NpgsqlCommand command = Command(connection, transaction, """
            update audit.audit_chain
            set current_sequence = @sequence, last_event_hash = @hash, updated_at = @now
            where chain_scope_type = @scope_type and chain_scope_id = @scope_id
            """);

        command.Parameters.AddWithValue("scope_type", chainScopeType);
        command.Parameters.AddWithValue("scope_id", chainScopeId);
        command.Parameters.AddWithValue("sequence", sequence);
        command.Parameters.AddWithValue("hash", eventHash);
        command.Parameters.AddWithValue("now", now);

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static NpgsqlCommand Command(NpgsqlConnection connection, NpgsqlTransaction transaction, string sql)
    {
        NpgsqlCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        return command;
    }

    private static void AddNullable(NpgsqlCommand command, string name, Guid? value)
        => command.Parameters.AddWithValue(name, value.HasValue ? value.Value : DBNull.Value);

    private static void AddNullable(NpgsqlCommand command, string name, string? value)
        => command.Parameters.AddWithValue(name, value is null ? DBNull.Value : value);
}
