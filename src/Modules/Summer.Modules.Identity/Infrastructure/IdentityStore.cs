using Npgsql;
using Summer.BuildingBlocks.Domain;
using Summer.Modules.Identity.Domain;

namespace Summer.Modules.Identity.Infrastructure;

/// <summary>
/// iam schema 的读写。DOM-IAM-001 只写本模块拥有的表（§4.3.1）。
///
/// 全部方法都要求外部传入事务：§4.6 规定业务聚合、关键流水与审计摘要同一事务，
/// 而 refresh 旋转更是必须「锁定 ACTIVE 行，原子标记 CONSUMED 并创建下一代」（§5.2.4）。
/// 把事务留给调用方，是为了不让本类自作主张切分事务边界。
/// </summary>
public sealed class IdentityStore(NpgsqlConnection connection, NpgsqlTransaction transaction)
{
    /// <summary>
    /// 当前事务的连接。暴露出来是为了让审计能写进**同一个**事务（§4.6）——
    /// 审计另开连接就意味着业务回滚时审计仍会留下，记录下没发生过的事。
    /// </summary>
    public NpgsqlConnection Connection => connection;

    public NpgsqlTransaction Transaction => transaction;

    private const string AccountColumns = """
        id, login_name_normalized, password_hash, session_version, failed_count,
        locked_until, last_login_at, password_changed_at, status, row_version
        """;

    private const string SessionColumns = """
        id, session_no, user_account_id, audience, organization_id, organization_member_id,
        session_version_snapshot, refresh_family_id, auth_strength, mfa_at,
        started_at, last_seen_at, expires_at, revoked_at, revoke_reason, status, row_version
        """;

    private const string TokenColumns = """
        id, session_id, family_id, generation, token_hash, issued_at, expires_at,
        consumed_at, replaced_by_token_id, revoked_at, revoke_reason, status, row_version
        """;

    // ---------------------------------------------------------------- 账号

    /// <summary>
    /// 按规范化登录名取账号并加行锁。
    /// 登录路径必须持锁读取：失败计数与锁定期是并发写的目标，
    /// 不加锁会让并行的错误口令尝试互相覆盖计数，绕过锁定阈值。
    /// </summary>
    public async Task<UserAccount?> LockAccountByLoginNameAsync(
        string loginNameNormalized, CancellationToken cancellationToken = default)
    {
        await using var command = Command($"""
            select {AccountColumns} from iam.user_account
            where login_name_normalized = @login
            for update
            """);
        command.Parameters.AddWithValue("login", loginNameNormalized);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadAccount(reader) : null;
    }

    public async Task<UserAccount?> LockAccountAsync(Guid id, CancellationToken cancellationToken = default)
    {
        await using var command = Command($"select {AccountColumns} from iam.user_account where id = @id for update");
        command.Parameters.AddWithValue("id", id);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadAccount(reader) : null;
    }

    public async Task InsertAccountAsync(UserAccount account, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(account);

        await using var command = Command("""
            insert into iam.user_account
                (id, login_name_normalized, password_hash, session_version, failed_count,
                 locked_until, last_login_at, password_changed_at, status,
                 created_at, created_by, updated_at, updated_by, row_version)
            values
                (@id, @login, @password_hash, @session_version, @failed_count,
                 @locked_until, @last_login_at, @password_changed_at, @status,
                 @now, @actor, @now, @actor, @row_version)
            """);

        command.Parameters.AddWithValue("id", account.Id);
        command.Parameters.AddWithValue("login", account.LoginNameNormalized);
        command.Parameters.AddWithValue("password_hash", account.PasswordHash);
        command.Parameters.AddWithValue("session_version", account.SessionVersion);
        command.Parameters.AddWithValue("failed_count", account.FailedCount);
        AddNullable(command, "locked_until", account.LockedUntil);
        AddNullable(command, "last_login_at", account.LastLoginAt);
        AddNullable(command, "password_changed_at", account.PasswordChangedAt);
        command.Parameters.AddWithValue("status", IdentityCodes.ToCode(account.Status));
        command.Parameters.AddWithValue("now", now);
        // 自助注册时创建证据指向账号自身：平台没有代为创建，写平台 actor 会伪造责任人。
        command.Parameters.AddWithValue("actor", account.Id);
        command.Parameters.AddWithValue("row_version", account.RowVersion.Value);

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    /// <summary>
    /// 按乐观锁更新账号。返回 false 表示 <c>row_version</c> 已被他人推进，
    /// 调用方应转 <c>CONC-VERSION-001</c> 而不是重试覆盖。
    /// </summary>
    public async Task<bool> UpdateAccountAsync(
        UserAccount account, RowVersion expected, DateTimeOffset now, Guid actor,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(account);

        await using var command = Command("""
            update iam.user_account set
                password_hash = @password_hash,
                session_version = @session_version,
                failed_count = @failed_count,
                locked_until = @locked_until,
                last_login_at = @last_login_at,
                password_changed_at = @password_changed_at,
                status = @status,
                updated_at = @now,
                updated_by = @actor,
                row_version = @row_version
            where id = @id and row_version = @expected
            """);

        command.Parameters.AddWithValue("id", account.Id);
        command.Parameters.AddWithValue("password_hash", account.PasswordHash);
        command.Parameters.AddWithValue("session_version", account.SessionVersion);
        command.Parameters.AddWithValue("failed_count", account.FailedCount);
        AddNullable(command, "locked_until", account.LockedUntil);
        AddNullable(command, "last_login_at", account.LastLoginAt);
        AddNullable(command, "password_changed_at", account.PasswordChangedAt);
        command.Parameters.AddWithValue("status", IdentityCodes.ToCode(account.Status));
        command.Parameters.AddWithValue("now", now);
        command.Parameters.AddWithValue("actor", actor);
        command.Parameters.AddWithValue("row_version", account.RowVersion.Value);
        command.Parameters.AddWithValue("expected", expected.Value);

        return await command.ExecuteNonQueryAsync(cancellationToken) == 1;
    }

    // ---------------------------------------------------------------- 会话

    public async Task InsertSessionAsync(UserSession session, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);

        await using var command = Command("""
            insert into iam.user_session
                (id, session_no, user_account_id, audience, organization_id, organization_member_id,
                 session_version_snapshot, refresh_family_id, auth_strength, mfa_at,
                 started_at, last_seen_at, expires_at, revoked_at, revoke_reason, status,
                 created_at, created_by, updated_at, updated_by, row_version)
            values
                (@id, @session_no, @user_account_id, @audience, @organization_id, @organization_member_id,
                 @session_version_snapshot, @refresh_family_id, @auth_strength, @mfa_at,
                 @started_at, @last_seen_at, @expires_at, @revoked_at, @revoke_reason, @status,
                 @now, @actor, @now, @actor, @row_version)
            """);

        BindSession(command, session);
        command.Parameters.AddWithValue("now", now);
        command.Parameters.AddWithValue("actor", session.UserAccountId);

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<UserSession?> LockSessionAsync(Guid id, CancellationToken cancellationToken = default)
    {
        await using var command = Command($"select {SessionColumns} from iam.user_session where id = @id for update");
        command.Parameters.AddWithValue("id", id);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadSession(reader) : null;
    }

    public async Task<bool> UpdateSessionAsync(
        UserSession session, RowVersion expected, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);

        await using var command = Command("""
            update iam.user_session set
                last_seen_at = @last_seen_at,
                expires_at = @expires_at,
                revoked_at = @revoked_at,
                revoke_reason = @revoke_reason,
                status = @status,
                updated_at = @now,
                updated_by = @actor,
                row_version = @row_version
            where id = @id and row_version = @expected
            """);

        BindSession(command, session);
        command.Parameters.AddWithValue("now", now);
        command.Parameters.AddWithValue("actor", session.UserAccountId);
        command.Parameters.AddWithValue("expected", expected.Value);

        return await command.ExecuteNonQueryAsync(cancellationToken) == 1;
    }

    /// <summary>
    /// 撤销账号名下全部 ACTIVE 会话。改密、停用、重放处置时调用（§7.2.4 第 8 条）。
    /// 返回受影响行数，供审计记录实际撤销范围。
    /// </summary>
    public async Task<int> RevokeActiveSessionsOfAccountAsync(
        Guid accountId, DateTimeOffset now, string reason, CancellationToken cancellationToken = default)
    {
        await using var command = Command("""
            update iam.user_session set
                status = 'REVOKED', revoked_at = @now, revoke_reason = @reason,
                updated_at = @now, updated_by = @actor, row_version = row_version + 1
            where user_account_id = @account_id and status = 'ACTIVE'
            """);

        command.Parameters.AddWithValue("account_id", accountId);
        command.Parameters.AddWithValue("now", now);
        command.Parameters.AddWithValue("reason", reason);
        command.Parameters.AddWithValue("actor", accountId);

        return await command.ExecuteNonQueryAsync(cancellationToken);
    }

    // ---------------------------------------------------------------- refresh token

    public async Task InsertRefreshTokenAsync(
        SessionRefreshToken token, DateTimeOffset now, Guid actor, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(token);

        await using var command = Command("""
            insert into iam.session_refresh_token
                (id, session_id, family_id, generation, token_hash, issued_at, expires_at,
                 consumed_at, replaced_by_token_id, revoked_at, revoke_reason, status,
                 created_at, created_by, updated_at, updated_by, row_version)
            values
                (@id, @session_id, @family_id, @generation, @token_hash, @issued_at, @expires_at,
                 @consumed_at, @replaced_by_token_id, @revoked_at, @revoke_reason, @status,
                 @now, @actor, @now, @actor, @row_version)
            """);

        BindToken(command, token);
        command.Parameters.AddWithValue("now", now);
        command.Parameters.AddWithValue("actor", actor);

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    /// <summary>
    /// 按摘要取令牌并加行锁。§5.2.4 要求刷新时锁定该行——
    /// 不加锁时两个并发刷新会读到同一 ACTIVE 行并都尝试消费，
    /// 唯一约束虽能挡住分叉，但错误会表现为约束冲突而非可诊断的重放判定。
    /// </summary>
    public async Task<SessionRefreshToken?> LockRefreshTokenByHashAsync(
        string tokenHash, CancellationToken cancellationToken = default)
    {
        await using var command = Command(
            $"select {TokenColumns} from iam.session_refresh_token where token_hash = @hash for update");
        command.Parameters.AddWithValue("hash", tokenHash);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadToken(reader) : null;
    }

    public async Task<bool> UpdateRefreshTokenAsync(
        SessionRefreshToken token, RowVersion expected, DateTimeOffset now, Guid actor,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(token);

        await using var command = Command("""
            update iam.session_refresh_token set
                consumed_at = @consumed_at,
                replaced_by_token_id = @replaced_by_token_id,
                revoked_at = @revoked_at,
                revoke_reason = @revoke_reason,
                status = @status,
                updated_at = @now,
                updated_by = @actor,
                row_version = @row_version
            where id = @id and row_version = @expected
            """);

        BindToken(command, token);
        command.Parameters.AddWithValue("now", now);
        command.Parameters.AddWithValue("actor", actor);
        command.Parameters.AddWithValue("expected", expected.Value);

        return await command.ExecuteNonQueryAsync(cancellationToken) == 1;
    }

    /// <summary>
    /// 撤销 family 内所有尚未终结的代。重放处置的一部分（§5.2.4）。
    /// 已 CONSUMED 的代保持原状：它们的消费历史是证据，改写会抹掉旋转链。
    /// </summary>
    public async Task<int> RevokeFamilyAsync(
        Guid familyId, DateTimeOffset now, string reason, Guid actor, CancellationToken cancellationToken = default)
    {
        await using var command = Command("""
            update iam.session_refresh_token set
                status = 'REVOKED', revoked_at = @now, revoke_reason = @reason,
                updated_at = @now, updated_by = @actor, row_version = row_version + 1
            where family_id = @family_id and status = 'ACTIVE'
            """);

        command.Parameters.AddWithValue("family_id", familyId);
        command.Parameters.AddWithValue("now", now);
        command.Parameters.AddWithValue("reason", reason);
        command.Parameters.AddWithValue("actor", actor);

        return await command.ExecuteNonQueryAsync(cancellationToken);
    }

    // ---------------------------------------------------------------- 映射

    private NpgsqlCommand Command(string sql)
    {
        NpgsqlCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        return command;
    }

    private static void AddNullable(NpgsqlCommand command, string name, DateTimeOffset? value)
        => command.Parameters.AddWithValue(name, value.HasValue ? value.Value : DBNull.Value);

    private static void AddNullable(NpgsqlCommand command, string name, Guid? value)
        => command.Parameters.AddWithValue(name, value.HasValue ? value.Value : DBNull.Value);

    private static void AddNullable(NpgsqlCommand command, string name, string? value)
        => command.Parameters.AddWithValue(name, value is null ? DBNull.Value : value);

    private static void BindSession(NpgsqlCommand command, UserSession session)
    {
        command.Parameters.AddWithValue("id", session.Id);
        command.Parameters.AddWithValue("session_no", session.SessionNo);
        command.Parameters.AddWithValue("user_account_id", session.UserAccountId);
        command.Parameters.AddWithValue("audience", AudienceCodes.ToCode(session.Audience));
        AddNullable(command, "organization_id", session.OrganizationId);
        AddNullable(command, "organization_member_id", session.OrganizationMemberId);
        command.Parameters.AddWithValue("session_version_snapshot", session.SessionVersionSnapshot);
        command.Parameters.AddWithValue("refresh_family_id", session.RefreshFamilyId);
        command.Parameters.AddWithValue("auth_strength", IdentityCodes.ToCode(session.AuthStrength));
        AddNullable(command, "mfa_at", session.MfaAt);
        command.Parameters.AddWithValue("started_at", session.StartedAt);
        command.Parameters.AddWithValue("last_seen_at", session.LastSeenAt);
        command.Parameters.AddWithValue("expires_at", session.ExpiresAt);
        AddNullable(command, "revoked_at", session.RevokedAt);
        AddNullable(command, "revoke_reason", session.RevokeReason);
        command.Parameters.AddWithValue("status", IdentityCodes.ToCode(session.Status));
        command.Parameters.AddWithValue("row_version", session.RowVersion.Value);
    }

    private static void BindToken(NpgsqlCommand command, SessionRefreshToken token)
    {
        command.Parameters.AddWithValue("id", token.Id);
        command.Parameters.AddWithValue("session_id", token.SessionId);
        command.Parameters.AddWithValue("family_id", token.FamilyId);
        command.Parameters.AddWithValue("generation", token.Generation);
        command.Parameters.AddWithValue("token_hash", token.TokenHash);
        command.Parameters.AddWithValue("issued_at", token.IssuedAt);
        command.Parameters.AddWithValue("expires_at", token.ExpiresAt);
        AddNullable(command, "consumed_at", token.ConsumedAt);
        AddNullable(command, "replaced_by_token_id", token.ReplacedByTokenId);
        AddNullable(command, "revoked_at", token.RevokedAt);
        AddNullable(command, "revoke_reason", token.RevokeReason);
        command.Parameters.AddWithValue("status", IdentityCodes.ToCode(token.Status));
        command.Parameters.AddWithValue("row_version", token.RowVersion.Value);
    }

    private static UserAccount ReadAccount(NpgsqlDataReader reader) => new()
    {
        Id = reader.GetGuid(0),
        LoginNameNormalized = reader.GetString(1),
        PasswordHash = reader.GetString(2),
        SessionVersion = reader.GetInt64(3),
        FailedCount = reader.GetInt32(4),
        LockedUntil = NullableTime(reader, 5),
        LastLoginAt = NullableTime(reader, 6),
        PasswordChangedAt = NullableTime(reader, 7),
        Status = IdentityCodes.ParseAccountStatus(reader.GetString(8)),
        RowVersion = new RowVersion(reader.GetInt64(9)),
    };

    private static UserSession ReadSession(NpgsqlDataReader reader) => new()
    {
        Id = reader.GetGuid(0),
        SessionNo = reader.GetString(1),
        UserAccountId = reader.GetGuid(2),
        Audience = AudienceCodes.Parse(reader.GetString(3)),
        OrganizationId = NullableGuid(reader, 4),
        OrganizationMemberId = NullableGuid(reader, 5),
        SessionVersionSnapshot = reader.GetInt64(6),
        RefreshFamilyId = reader.GetGuid(7),
        AuthStrength = IdentityCodes.ParseAuthStrength(reader.GetString(8)),
        MfaAt = NullableTime(reader, 9),
        StartedAt = reader.GetFieldValue<DateTimeOffset>(10),
        LastSeenAt = reader.GetFieldValue<DateTimeOffset>(11),
        ExpiresAt = reader.GetFieldValue<DateTimeOffset>(12),
        RevokedAt = NullableTime(reader, 13),
        RevokeReason = reader.IsDBNull(14) ? null : reader.GetString(14),
        Status = IdentityCodes.ParseSessionStatus(reader.GetString(15)),
        RowVersion = new RowVersion(reader.GetInt64(16)),
    };

    private static SessionRefreshToken ReadToken(NpgsqlDataReader reader) => new()
    {
        Id = reader.GetGuid(0),
        SessionId = reader.GetGuid(1),
        FamilyId = reader.GetGuid(2),
        Generation = reader.GetInt32(3),
        TokenHash = reader.GetString(4),
        IssuedAt = reader.GetFieldValue<DateTimeOffset>(5),
        ExpiresAt = reader.GetFieldValue<DateTimeOffset>(6),
        ConsumedAt = NullableTime(reader, 7),
        ReplacedByTokenId = NullableGuid(reader, 8),
        RevokedAt = NullableTime(reader, 9),
        RevokeReason = reader.IsDBNull(10) ? null : reader.GetString(10),
        Status = IdentityCodes.ParseRefreshTokenStatus(reader.GetString(11)),
        RowVersion = new RowVersion(reader.GetInt64(12)),
    };

    private static DateTimeOffset? NullableTime(NpgsqlDataReader reader, int ordinal)
        => reader.IsDBNull(ordinal) ? null : reader.GetFieldValue<DateTimeOffset>(ordinal);

    private static Guid? NullableGuid(NpgsqlDataReader reader, int ordinal)
        => reader.IsDBNull(ordinal) ? null : reader.GetGuid(ordinal);
}
