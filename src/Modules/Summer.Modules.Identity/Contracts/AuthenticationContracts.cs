using Summer.BuildingBlocks.Domain;

namespace Summer.Modules.Identity.Contracts;

/// <summary>
/// 登录命令。
/// §4.6：API 不接受客户端覆盖 organization_id、workspace_id 或 Audience——
/// 但**首次选择受众**是例外，§7.2.4 第 4 步明确由用户选择受众与合法主体。
/// 区别在于：这里的选择要经服务端校验成员关系与能力后才冻结进会话，
/// 而不是把客户端提交的值当作可信上下文。
/// </summary>
public sealed record LoginCommand
{
    public required string LoginName { get; init; }

    public required string Password { get; init; }

    public required Audience Audience { get; init; }

    /// <summary>PROVIDER/ENTERPRISE 必填，由服务端校验后冻结；PLATFORM 必须为空。</summary>
    public Guid? OrganizationId { get; init; }

    public Guid? OrganizationMemberId { get; init; }

    /// <summary>§3.1 第 1 条：改变状态的命令必须携带幂等键。</summary>
    public required string IdempotencyKey { get; init; }

    public string? CorrelationId { get; init; }
}

/// <summary>
/// 登录/刷新的成功结果。
///
/// <see cref="RefreshToken"/> 是**唯一一次**返回原值的时机：库里只有摘要（§7.2.4）。
/// </summary>
public sealed record SessionIssued
{
    public required Guid SessionId { get; init; }

    public required string SessionNo { get; init; }

    public required string RefreshToken { get; init; }

    public required DateTimeOffset ExpiresAt { get; init; }

    public required DateTimeOffset RefreshTokenExpiresAt { get; init; }
}

/// <summary>刷新命令。</summary>
public sealed record RefreshCommand
{
    public required string RefreshToken { get; init; }

    public required string IdempotencyKey { get; init; }

    public string? CorrelationId { get; init; }
}

/// <summary>登出命令。§7.2.4：不得仅依靠前端删除令牌实现注销。</summary>
public sealed record LogoutCommand
{
    public required Guid SessionId { get; init; }

    public required string IdempotencyKey { get; init; }

    public string? CorrelationId { get; init; }
}
