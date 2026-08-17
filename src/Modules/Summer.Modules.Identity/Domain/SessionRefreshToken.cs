using Summer.BuildingBlocks.Domain;

namespace Summer.Modules.Identity.Domain;

/// <summary>
/// ENT-IAM-002 <c>session_refresh_token</c>（docs/04-系统设计.md §5.2.4、§6）。
///
/// family + 单次旋转：每代只能被消费一次，消费旧代与签发新代必须同一事务。
/// 已消费代再次出现即视为重放，撤销整个 family 与 session 并递增账号安全版本。
/// </summary>
public sealed record SessionRefreshToken
{
    public required Guid Id { get; init; }

    public required Guid SessionId { get; init; }

    public required Guid FamilyId { get; init; }

    /// <summary>family 内单调代号，从 1 开始。<c>unique(family_id, generation)</c> 阻止分叉。</summary>
    public required int Generation { get; init; }

    /// <summary>令牌摘要。原值只在签发那一刻返回给客户端，不落库（§7.2.4）。</summary>
    public required string TokenHash { get; init; }

    public required DateTimeOffset IssuedAt { get; init; }

    public required DateTimeOffset ExpiresAt { get; init; }

    public DateTimeOffset? ConsumedAt { get; init; }

    public Guid? ReplacedByTokenId { get; init; }

    public DateTimeOffset? RevokedAt { get; init; }

    public string? RevokeReason { get; init; }

    public required RefreshTokenStatus Status { get; init; }

    public required RowVersion RowVersion { get; init; }

    /// <summary>签发某一代令牌。</summary>
    public static SessionRefreshToken Issue(
        Guid id,
        Guid sessionId,
        Guid familyId,
        int generation,
        string tokenHash,
        DateTimeOffset now,
        SessionPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentException.ThrowIfNullOrEmpty(tokenHash);
        ArgumentOutOfRangeException.ThrowIfLessThan(generation, 1);

        return new SessionRefreshToken
        {
            Id = id,
            SessionId = sessionId,
            FamilyId = familyId,
            Generation = generation,
            TokenHash = tokenHash,
            IssuedAt = now,
            ExpiresAt = now + policy.RefreshTokenLifetime,
            Status = RefreshTokenStatus.Active,
            RowVersion = RowVersion.Initial,
        };
    }

    /// <summary>标记为已消费，并指向后继代。两者必须同时写入，见 DDL 的 CONSUMED 检查约束。</summary>
    public SessionRefreshToken Consume(DateTimeOffset now, Guid replacedByTokenId)
        => this with
        {
            Status = RefreshTokenStatus.Consumed,
            ConsumedAt = now,
            ReplacedByTokenId = replacedByTokenId,
            RowVersion = RowVersion.Next(),
        };

    /// <summary>撤销。用于重放处置时收口 family 内其余各代。</summary>
    public SessionRefreshToken Revoke(DateTimeOffset now, string reason)
    {
        ArgumentException.ThrowIfNullOrEmpty(reason);

        return this with
        {
            Status = RefreshTokenStatus.Revoked,
            RevokedAt = now,
            RevokeReason = reason,
            RowVersion = RowVersion.Next(),
        };
    }

    /// <summary>标记为重放证据。REUSED 记在被重放的那一代上，不覆盖其 CONSUMED 历史含义。</summary>
    public SessionRefreshToken MarkReused(DateTimeOffset now, string reason)
    {
        ArgumentException.ThrowIfNullOrEmpty(reason);

        return this with
        {
            Status = RefreshTokenStatus.Reused,
            RevokedAt = now,
            RevokeReason = reason,
            RowVersion = RowVersion.Next(),
        };
    }

    /// <summary>该代是否可用于换取下一代。</summary>
    public bool IsRedeemable(DateTimeOffset now)
        => Status is RefreshTokenStatus.Active && now < ExpiresAt;
}
