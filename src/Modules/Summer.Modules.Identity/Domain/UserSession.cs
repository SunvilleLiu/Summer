using Summer.BuildingBlocks.Application;
using Summer.BuildingBlocks.Domain;

namespace Summer.Modules.Identity.Domain;

/// <summary>会话失效原因。仅用于审计与内部分支，不直接对外暴露。</summary>
public enum SessionInvalidReason
{
    None,

    /// <summary>会话已 EXPIRED 或 REVOKED。§3.3.1：终态不可恢复。</summary>
    Terminal,

    /// <summary>已过 <c>expires_at</c>，但行上仍是 ACTIVE（尚未被清理批处理收口）。</summary>
    Expired,

    /// <summary>账号安全版本已变（改密、停用、风险处置、refresh 重放）。</summary>
    SecurityVersionChanged,
}

/// <summary>
/// ENT-IAM-002 <c>user_session</c>（docs/04-系统设计.md §5.2.4）。
///
/// 受众、账号与 Organization 上下文在创建时冻结（标记 I），此后不原地修改：
/// 切换受众或 Organization 必须新建会话并撤销旧会话（§7.2.4 第 7 条）。
/// </summary>
public sealed record UserSession
{
    public required Guid Id { get; init; }

    /// <summary>全局唯一安全外显号。不可枚举，因此取随机值而非序列。</summary>
    public required string SessionNo { get; init; }

    public required Guid UserAccountId { get; init; }

    public required Audience Audience { get; init; }

    /// <summary>PLATFORM 恒为 null；PROVIDER/ENTERPRISE 必填（§4.2.3）。</summary>
    public Guid? OrganizationId { get; init; }

    public Guid? OrganizationMemberId { get; init; }

    public required long SessionVersionSnapshot { get; init; }

    public required Guid RefreshFamilyId { get; init; }

    public required AuthStrength AuthStrength { get; init; }

    public DateTimeOffset? MfaAt { get; init; }

    public required DateTimeOffset StartedAt { get; init; }

    public required DateTimeOffset LastSeenAt { get; init; }

    public required DateTimeOffset ExpiresAt { get; init; }

    public DateTimeOffset? RevokedAt { get; init; }

    public string? RevokeReason { get; init; }

    public required SessionStatus Status { get; init; }

    public required RowVersion RowVersion { get; init; }

    /// <summary>
    /// 建立受众冻结的会话。
    /// Organization 上下文与受众的对应关系在此校验一次，DDL 的
    /// <c>ck_user_session_audience_scope</c> 再兜一次——应用层的错误不该靠数据库先发现，
    /// 但数据库必须挡得住绕过应用层的写入。
    /// </summary>
    public static UserSession Start(
        Guid id,
        UserAccount account,
        Audience audience,
        Guid? organizationId,
        Guid? organizationMemberId,
        AuthStrength authStrength,
        DateTimeOffset now,
        SessionPolicy policy,
        Guid refreshFamilyId,
        string sessionNo)
    {
        ArgumentNullException.ThrowIfNull(account);
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentException.ThrowIfNullOrEmpty(sessionNo);

        bool requiresOrganization = AudienceCodes.RequiresOrganization(audience);
        if (requiresOrganization && (organizationId is null || organizationMemberId is null))
        {
            throw new ArgumentException(
                $"{AudienceCodes.ToCode(audience)} 会话必须冻结 organization_id 与 organization_member_id（§5.2.4）",
                nameof(organizationId));
        }

        if (!requiresOrganization && (organizationId is not null || organizationMemberId is not null))
        {
            throw new ArgumentException(
                "PLATFORM 会话不得携带 Organization 业务上下文（§4.2.3）", nameof(organizationId));
        }

        return new UserSession
        {
            Id = id,
            SessionNo = sessionNo,
            UserAccountId = account.Id,
            Audience = audience,
            OrganizationId = organizationId,
            OrganizationMemberId = organizationMemberId,
            SessionVersionSnapshot = account.SessionVersion,
            RefreshFamilyId = refreshFamilyId,
            AuthStrength = authStrength,
            MfaAt = authStrength is AuthStrength.Mfa or AuthStrength.Reauth ? now : null,
            StartedAt = now,
            LastSeenAt = now,
            ExpiresAt = now + policy.AccessTokenLifetime,
            Status = SessionStatus.Active,
            RowVersion = RowVersion.Initial,
        };
    }

    /// <summary>
    /// 逐请求重新求值会话是否仍然可用（§4.1 结论 6：后端逐请求重新求值）。
    /// </summary>
    public SessionInvalidReason Validate(long currentAccountSessionVersion, DateTimeOffset now)
    {
        if (Status is not SessionStatus.Active)
        {
            return SessionInvalidReason.Terminal;
        }

        if (now >= ExpiresAt)
        {
            return SessionInvalidReason.Expired;
        }

        if (SessionVersionSnapshot != currentAccountSessionVersion)
        {
            return SessionInvalidReason.SecurityVersionChanged;
        }

        return SessionInvalidReason.None;
    }

    /// <summary>撤销。终态不可恢复，因此对已终态会话再次撤销直接返回原值（幂等）。</summary>
    public UserSession Revoke(DateTimeOffset now, string reason)
    {
        ArgumentException.ThrowIfNullOrEmpty(reason);

        if (Status is not SessionStatus.Active)
        {
            return this;
        }

        return this with
        {
            Status = SessionStatus.Revoked,
            RevokedAt = now,
            RevokeReason = reason,
            RowVersion = RowVersion.Next(),
        };
    }

    /// <summary>刷新时延长有效期并推进最后活跃时间。</summary>
    public UserSession Renew(DateTimeOffset now, SessionPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);

        return this with
        {
            LastSeenAt = now,
            ExpiresAt = now + policy.AccessTokenLifetime,
            RowVersion = RowVersion.Next(),
        };
    }

    /// <summary>生成不可枚举的会话外显号。</summary>
    public static string NewSessionNo() => $"SES-{SecretHash.NewSecret()[..24]}";
}
