using Npgsql;
using Summer.BuildingBlocks.Application;
using Summer.BuildingBlocks.Domain;
using Summer.BuildingBlocks.Infrastructure;
using Summer.Modules.Identity.Contracts;
using Summer.Modules.Identity.Domain;
using Summer.Modules.Identity.Infrastructure;

namespace Summer.Modules.Identity.Application;

/// <summary>
/// DOM-IAM-001 的登录、刷新与登出。
///
/// 三条贯穿全类的规则：
/// 1. 对外失败一律统一响应，差异只进审计（§7.2.5 反枚举）；
/// 2. 每个命令一个事务，聚合与审计同事务写入（§4.6）；
/// 3. 会话终态不可恢复，refresh 每代只能消费一次（§3.3.1、§5.2.4）。
/// </summary>
public sealed class AuthenticationService(
    DatabaseOptions databaseOptions,
    SessionPolicy policy,
    IClock clock,
    IAuditSink auditSink,
    IOrganizationContextVerifier? organizationVerifier = null)
{
    /// <summary>
    /// 登录名不存在时用于消耗等量算力的占位哈希。
    /// 不做这一步的话，「账号是否存在」可以直接从响应耗时读出来，
    /// 统一错误码就白设了。
    /// </summary>
    private static readonly Lazy<string> TimingEqualizerHash =
        new(() => PasswordHasher.Hash(Guid.NewGuid().ToString("N")));

    private const string ReasonLogin = "LOGIN";
    private const string ReasonRefresh = "REFRESH_ROTATE";
    private const string ReasonLogout = "LOGOUT";
    private const string ReasonRefreshReuse = "REFRESH_REUSE_DETECTED";

    /// <summary>统一的第一因素失败响应。三种失败情形共用，调用方无法区分。</summary>
    private static DomainError CredentialRejected(string auditDetail)
        => DomainError.Of(ErrorCodes.AuthCredentialRejected, "登录名或口令不正确", auditDetail);

    // ================================================================ 登录

    public async Task<Result<SessionIssued>> LoginAsync(
        LoginCommand command, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);

        DateTimeOffset now = clock.UtcNow;
        string loginName = NormalizeLoginName(command.LoginName);

        await using NpgsqlConnection connection = new(databaseOptions.ConnectionString);
        await connection.OpenAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        var store = new IdentityStore(connection, transaction);

        UserAccount? account = await store.LockAccountByLoginNameAsync(loginName, cancellationToken);

        if (account is null)
        {
            PasswordHasher.Verify(command.Password, TimingEqualizerHash.Value);
            await WriteAuditAsync(store, FailureAudit(now, null, command, "ACCOUNT_NOT_FOUND"), cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return CredentialRejected("登录名不存在");
        }

        RowVersion expected = account.RowVersion;
        (UserAccount next, LoginOutcome outcome) = account.Authenticate(command.Password, now, policy);

        if (outcome is not LoginOutcome.Succeeded)
        {
            // 失败也要落库：失败计数与锁定期是安全事实，回滚掉等于没有登录保护。
            if (!ReferenceEquals(next, account))
            {
                await store.UpdateAccountAsync(next, expected, now, account.Id, cancellationToken);
            }

            await WriteAuditAsync(store, FailureAudit(now, account.Id, command, outcome.ToString()), cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return CredentialRejected($"第一因素失败：{outcome}");
        }

        // 受众要求 Organization 上下文时，必须由 DOM-ORG-001 校验成员关系与能力。
        Result<bool> contextCheck = await VerifyAudienceContextAsync(command, account.Id, cancellationToken);
        if (!contextCheck.IsSuccess)
        {
            await WriteAuditAsync(
                store, FailureAudit(now, account.Id, command, contextCheck.Error!.Code), cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return Result.Failure<SessionIssued>(contextCheck.Error);
        }

        if (!await store.UpdateAccountAsync(next, expected, now, account.Id, cancellationToken))
        {
            await transaction.RollbackAsync(cancellationToken);
            return DomainError.Of(ErrorCodes.ConcurrencyVersion, "账号状态已被并发修改，请重试");
        }

        SessionIssued issued = await StartSessionAsync(store, next, command, now, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return Result.Success(issued);
    }

    private async Task<Result<bool>> VerifyAudienceContextAsync(
        LoginCommand command, Guid accountId, CancellationToken cancellationToken)
    {
        if (!AudienceCodes.RequiresOrganization(command.Audience))
        {
            // PLATFORM 会话不得携带 Organization 上下文；客户端提交了就是越权尝试。
            if (command.OrganizationId is not null || command.OrganizationMemberId is not null)
            {
                return DomainError.Of(
                    ErrorCodes.ForbiddenClientScope, "PLATFORM 会话不得提交 Organization 上下文");
            }

            return Result.Success(true);
        }

        if (command.OrganizationId is not { } organizationId ||
            command.OrganizationMemberId is not { } memberId)
        {
            return DomainError.Of(ErrorCodes.AudienceMismatch, "该受众必须指定 Organization 与成员身份");
        }

        if (organizationVerifier is null)
        {
            // DOM-ORG-001 的查询契约尚无实现。此处失败关闭，不放行——
            // 「查不到就放行」会让受众隔离在 Organization 模块交付前就形同虚设。
            return DomainError.Of(
                ErrorCodes.OrganizationCapability,
                "无法校验 Organization 上下文",
                "IOrganizationContextVerifier 未注入，PROVIDER/ENTERPRISE 会话失败关闭");
        }

        string capability = command.Audience is Audience.Provider
            ? CapabilityCodes.ProvideService
            : CapabilityCodes.ReceiveService;

        OrganizationContextVerdict verdict = await organizationVerifier.VerifyAsync(
            accountId, organizationId, memberId, capability, cancellationToken);

        return verdict.Allowed
            ? Result.Success(true)
            : DomainError.Of(ErrorCodes.OrganizationCapability, "无法以该身份建立会话", verdict.ReasonCode);
    }

    private async Task<SessionIssued> StartSessionAsync(
        IdentityStore store, UserAccount account, LoginCommand command,
        DateTimeOffset now, CancellationToken cancellationToken)
    {
        Guid familyId = Guid.NewGuid();
        UserSession session = UserSession.Start(
            id: Guid.NewGuid(),
            account: account,
            audience: command.Audience,
            organizationId: command.OrganizationId,
            organizationMemberId: command.OrganizationMemberId,
            authStrength: AuthStrength.Password,
            now: now,
            policy: policy,
            refreshFamilyId: familyId,
            sessionNo: UserSession.NewSessionNo());

        await store.InsertSessionAsync(session, now, cancellationToken);

        (string secret, SessionRefreshToken token) = IssueToken(session.Id, familyId, 1, now);
        await store.InsertRefreshTokenAsync(token, now, account.Id, cancellationToken);

        await WriteAuditAsync(store, new AuditEntry
        {
            EventType = "iam.session.started",
            OccurredAt = now,
            ActorAccountId = account.Id,
            AudienceCode = AudienceCodes.ToCode(session.Audience),
            OrganizationId = session.OrganizationId,
            ObjectType = "user_session",
            ObjectId = session.Id,
            ToStatus = IdentityCodes.ToCode(SessionStatus.Active),
            ReasonCode = ReasonLogin,
            IdempotencyKey = command.IdempotencyKey,
            CorrelationId = command.CorrelationId,
        }, cancellationToken);

        return new SessionIssued
        {
            SessionId = session.Id,
            SessionNo = session.SessionNo,
            RefreshToken = secret,
            ExpiresAt = session.ExpiresAt,
            RefreshTokenExpiresAt = token.ExpiresAt,
        };
    }

    // ================================================================ 刷新

    /// <summary>
    /// family 单次旋转。
    ///
    /// §5.2.4 的三条硬要求在此实现：锁定 ACTIVE 行、同事务消费旧代并创建下一代、
    /// 已消费代重现即撤销整个 family 与 session 并递增账号安全版本。
    /// </summary>
    public async Task<Result<SessionIssued>> RefreshAsync(
        RefreshCommand command, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);

        DateTimeOffset now = clock.UtcNow;
        string tokenHash = SecretHash.Of(command.RefreshToken);

        await using NpgsqlConnection connection = new(databaseOptions.ConnectionString);
        await connection.OpenAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        var store = new IdentityStore(connection, transaction);

        SessionRefreshToken? presented = await store.LockRefreshTokenByHashAsync(tokenHash, cancellationToken);
        if (presented is null)
        {
            await transaction.RollbackAsync(cancellationToken);
            return DomainError.Of(ErrorCodes.AuthTokenInvalid, "令牌无效", "refresh token 摘要未命中");
        }

        // 已消费代重现 = 重放。整个 family 与 session 立即失效，并递增账号安全版本。
        if (presented.Status is RefreshTokenStatus.Consumed)
        {
            await HandleReuseAsync(store, presented, command, now, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return DomainError.Of(
                ErrorCodes.AuthRefreshReuse, "令牌已失效，请重新登录", "检测到已消费代重放，family 已整体撤销");
        }

        if (!presented.IsRedeemable(now))
        {
            await transaction.RollbackAsync(cancellationToken);
            return DomainError.Of(
                ErrorCodes.AuthTokenInvalid, "令牌无效", $"令牌不可兑换：status={presented.Status}");
        }

        UserSession? session = await store.LockSessionAsync(presented.SessionId, cancellationToken);
        if (session is null)
        {
            await transaction.RollbackAsync(cancellationToken);
            return DomainError.Of(ErrorCodes.AuthSessionTerminal, "会话不可用");
        }

        UserAccount? account = await store.LockAccountAsync(session.UserAccountId, cancellationToken);
        if (account is null)
        {
            await transaction.RollbackAsync(cancellationToken);
            return DomainError.Of(ErrorCodes.AuthSessionTerminal, "会话不可用");
        }

        SessionInvalidReason invalid = session.Validate(account.SessionVersion, now);
        if (invalid is not SessionInvalidReason.None)
        {
            await transaction.RollbackAsync(cancellationToken);
            return DomainError.Of(ErrorCodes.AuthSessionTerminal, "会话不可用", $"会话失效：{invalid}");
        }

        if (account.Status is not AccountStatus.Active)
        {
            await transaction.RollbackAsync(cancellationToken);
            return DomainError.Of(ErrorCodes.AuthSessionTerminal, "会话不可用", $"账号状态：{account.Status}");
        }

        // 先建下一代再消费当代：CONSUMED 行的 replaced_by_token_id 有非空检查约束，
        // 顺序反过来会撞约束。unique(family_id, generation) 使并发刷新只有一方能走到这里。
        (string secret, SessionRefreshToken nextToken) =
            IssueToken(session.Id, presented.FamilyId, presented.Generation + 1, now);
        await store.InsertRefreshTokenAsync(nextToken, now, account.Id, cancellationToken);

        SessionRefreshToken consumed = presented.Consume(now, nextToken.Id);
        if (!await store.UpdateRefreshTokenAsync(consumed, presented.RowVersion, now, account.Id, cancellationToken))
        {
            await transaction.RollbackAsync(cancellationToken);
            return DomainError.Of(ErrorCodes.ConcurrencyVersion, "令牌已被并发使用，请重试");
        }

        UserSession renewed = session.Renew(now, policy);
        if (!await store.UpdateSessionAsync(renewed, session.RowVersion, now, cancellationToken))
        {
            await transaction.RollbackAsync(cancellationToken);
            return DomainError.Of(ErrorCodes.ConcurrencyVersion, "会话已被并发修改，请重试");
        }

        await WriteAuditAsync(store, new AuditEntry
        {
            EventType = "iam.session.refreshed",
            OccurredAt = now,
            ActorAccountId = account.Id,
            AudienceCode = AudienceCodes.ToCode(session.Audience),
            OrganizationId = session.OrganizationId,
            ObjectType = "session_refresh_token",
            ObjectId = nextToken.Id,
            FromStatus = IdentityCodes.ToCode(RefreshTokenStatus.Active),
            ToStatus = IdentityCodes.ToCode(RefreshTokenStatus.Active),
            ReasonCode = ReasonRefresh,
            IdempotencyKey = command.IdempotencyKey,
            CorrelationId = command.CorrelationId,
        }, cancellationToken);

        await transaction.CommitAsync(cancellationToken);

        return Result.Success(new SessionIssued
        {
            SessionId = renewed.Id,
            SessionNo = renewed.SessionNo,
            RefreshToken = secret,
            ExpiresAt = renewed.ExpiresAt,
            RefreshTokenExpiresAt = nextToken.ExpiresAt,
        });
    }

    /// <summary>
    /// 重放处置。§5.2.4：事务内撤销整个 family 和 session、递增账号 session_version
    /// 并产生高风险审计。四件事缺一不可，因此都在调用方的同一事务里完成。
    /// </summary>
    private async Task HandleReuseAsync(
        IdentityStore store, SessionRefreshToken replayed, RefreshCommand command,
        DateTimeOffset now, CancellationToken cancellationToken)
    {
        SessionRefreshToken marked = replayed.MarkReused(now, ReasonRefreshReuse);
        await store.UpdateRefreshTokenAsync(marked, replayed.RowVersion, now, replayed.SessionId, cancellationToken);
        await store.RevokeFamilyAsync(replayed.FamilyId, now, ReasonRefreshReuse, replayed.SessionId, cancellationToken);

        UserSession? session = await store.LockSessionAsync(replayed.SessionId, cancellationToken);
        Guid? accountId = session?.UserAccountId;

        if (session is not null)
        {
            UserSession revoked = session.Revoke(now, ReasonRefreshReuse);
            await store.UpdateSessionAsync(revoked, session.RowVersion, now, cancellationToken);

            UserAccount? account = await store.LockAccountAsync(session.UserAccountId, cancellationToken);
            if (account is not null)
            {
                // 递增安全版本使该账号**全部**会话失效，而不只是被重放的这一个：
                // 令牌已经泄露，攻击者可能同时持有其他会话的凭据。
                UserAccount bumped = account.BumpSessionVersion();
                await store.UpdateAccountAsync(bumped, account.RowVersion, now, account.Id, cancellationToken);
                await store.RevokeActiveSessionsOfAccountAsync(
                    account.Id, now, ReasonRefreshReuse, cancellationToken);
            }
        }

        await WriteAuditAsync(store, new AuditEntry
        {
            EventType = "iam.session.refresh_reuse_detected",
            OccurredAt = now,
            ActorAccountId = accountId,
            AudienceCode = session is null ? null : AudienceCodes.ToCode(session.Audience),
            OrganizationId = session?.OrganizationId,
            ObjectType = "session_refresh_token",
            ObjectId = replayed.Id,
            FromStatus = IdentityCodes.ToCode(RefreshTokenStatus.Consumed),
            ToStatus = IdentityCodes.ToCode(RefreshTokenStatus.Reused),
            ReasonCode = ReasonRefreshReuse,
            IdempotencyKey = command.IdempotencyKey,
            CorrelationId = command.CorrelationId,
            Risk = AuditRisk.High,
        }, cancellationToken);
    }

    // ================================================================ 登出

    /// <summary>
    /// 撤销会话与其 family。§7.2.4：不得仅依靠前端删除令牌实现注销。
    /// 对已终态会话幂等返回成功——重复登出不是错误。
    /// </summary>
    public async Task<Result<bool>> LogoutAsync(
        LogoutCommand command, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);

        DateTimeOffset now = clock.UtcNow;

        await using NpgsqlConnection connection = new(databaseOptions.ConnectionString);
        await connection.OpenAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        var store = new IdentityStore(connection, transaction);

        UserSession? session = await store.LockSessionAsync(command.SessionId, cancellationToken);
        if (session is null)
        {
            await transaction.RollbackAsync(cancellationToken);
            return DomainError.Of(ErrorCodes.AuthSessionTerminal, "会话不可用");
        }

        if (session.Status is not SessionStatus.Active)
        {
            await transaction.CommitAsync(cancellationToken);
            return Result.Success(true);
        }

        UserSession revoked = session.Revoke(now, ReasonLogout);
        if (!await store.UpdateSessionAsync(revoked, session.RowVersion, now, cancellationToken))
        {
            await transaction.RollbackAsync(cancellationToken);
            return DomainError.Of(ErrorCodes.ConcurrencyVersion, "会话已被并发修改，请重试");
        }

        await store.RevokeFamilyAsync(
            session.RefreshFamilyId, now, ReasonLogout, session.UserAccountId, cancellationToken);

        await WriteAuditAsync(store, new AuditEntry
        {
            EventType = "iam.session.revoked",
            OccurredAt = now,
            ActorAccountId = session.UserAccountId,
            AudienceCode = AudienceCodes.ToCode(session.Audience),
            OrganizationId = session.OrganizationId,
            ObjectType = "user_session",
            ObjectId = session.Id,
            FromStatus = IdentityCodes.ToCode(SessionStatus.Active),
            ToStatus = IdentityCodes.ToCode(SessionStatus.Revoked),
            ReasonCode = ReasonLogout,
            IdempotencyKey = command.IdempotencyKey,
            CorrelationId = command.CorrelationId,
        }, cancellationToken);

        await transaction.CommitAsync(cancellationToken);
        return Result.Success(true);
    }

    // ================================================================ 会话校验

    /// <summary>
    /// 逐请求重新求值会话（§4.1 结论 6）。
    /// 返回可用会话，或统一的失效错误——调用方不该据错误区分失效原因。
    /// </summary>
    public async Task<Result<UserSession>> ValidateSessionAsync(
        Guid sessionId, CancellationToken cancellationToken = default)
    {
        DateTimeOffset now = clock.UtcNow;

        await using NpgsqlConnection connection = new(databaseOptions.ConnectionString);
        await connection.OpenAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        var store = new IdentityStore(connection, transaction);

        UserSession? session = await store.LockSessionAsync(sessionId, cancellationToken);
        if (session is null)
        {
            await transaction.RollbackAsync(cancellationToken);
            return DomainError.Of(ErrorCodes.AuthTokenInvalid, "会话不可用");
        }

        UserAccount? account = await store.LockAccountAsync(session.UserAccountId, cancellationToken);
        if (account is null)
        {
            await transaction.RollbackAsync(cancellationToken);
            return DomainError.Of(ErrorCodes.AuthTokenInvalid, "会话不可用");
        }

        SessionInvalidReason invalid = session.Validate(account.SessionVersion, now);
        if (invalid is not SessionInvalidReason.None)
        {
            await transaction.RollbackAsync(cancellationToken);
            return DomainError.Of(ErrorCodes.AuthTokenInvalid, "会话不可用", $"会话失效：{invalid}");
        }

        if (account.Status is not AccountStatus.Active)
        {
            await transaction.RollbackAsync(cancellationToken);
            return DomainError.Of(ErrorCodes.AuthTokenInvalid, "会话不可用", $"账号状态：{account.Status}");
        }

        await transaction.CommitAsync(cancellationToken);
        return Result.Success(session);
    }

    // ================================================================ 辅助

    private (string Secret, SessionRefreshToken Token) IssueToken(
        Guid sessionId, Guid familyId, int generation, DateTimeOffset now)
    {
        string secret = SecretHash.NewSecret();
        SessionRefreshToken token = SessionRefreshToken.Issue(
            Guid.NewGuid(), sessionId, familyId, generation, SecretHash.Of(secret), now, policy);
        return (secret, token);
    }

    private static AuditEntry FailureAudit(
        DateTimeOffset now, Guid? accountId, LoginCommand command, string reasonCode) => new()
        {
            EventType = "iam.login.rejected",
            OccurredAt = now,
            ActorAccountId = accountId,
            AudienceCode = AudienceCodes.ToCode(command.Audience),
            ReasonCode = reasonCode,
            IdempotencyKey = command.IdempotencyKey,
            CorrelationId = command.CorrelationId,
            Risk = AuditRisk.High,
        };

    /// <summary>
    /// 把审计事实写进当前事务。§4.6：业务聚合、关键流水与审计摘要同一事务。
    /// </summary>
    private Task WriteAuditAsync(IdentityStore store, AuditEntry entry, CancellationToken cancellationToken)
        => auditSink.WriteAsync(entry, store.Connection, store.Transaction, cancellationToken);

    /// <summary>
    /// 登录名规范化。§5.2.2 的唯一约束建在 <c>login_name_normalized</c> 上，
    /// 写入与查询必须用同一套规范化，否则唯一性会被大小写绕过。
    /// </summary>
    public static string NormalizeLoginName(string loginName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(loginName);
        return loginName.Trim().ToLowerInvariant();
    }
}
