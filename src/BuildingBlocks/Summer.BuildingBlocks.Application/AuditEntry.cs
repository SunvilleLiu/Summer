namespace Summer.BuildingBlocks.Application;

/// <summary>
/// 一条审计事实。字段取 §3.1 第 3 条的最小集合：
/// Organization、Workspace、业务对象、前后状态、操作者、受众、原因、命令号和发生时间。
/// PLATFORM 受众下 Organization/Workspace 为空，不伪造（§1.8.3）。
/// </summary>
public sealed record AuditEntry
{
    public required string EventType { get; init; }

    public required DateTimeOffset OccurredAt { get; init; }

    /// <summary>操作者账号。匿名失败（如登录名不存在）时为 null。</summary>
    public Guid? ActorAccountId { get; init; }

    /// <summary>受众代码。未建立会话前为 null。</summary>
    public string? AudienceCode { get; init; }

    public Guid? OrganizationId { get; init; }

    public Guid? WorkspaceId { get; init; }

    /// <summary>业务对象类型与标识，例如 <c>user_session</c> + 会话 id。</summary>
    public string? ObjectType { get; init; }

    public Guid? ObjectId { get; init; }

    public string? FromStatus { get; init; }

    public string? ToStatus { get; init; }

    /// <summary>稳定原因代码，不用中文名判断（§1.8.1）。</summary>
    public string? ReasonCode { get; init; }

    /// <summary>命令幂等键，用于把审计与命令对齐（§3.1 第 1 条）。</summary>
    public string? IdempotencyKey { get; init; }

    public string? CorrelationId { get; init; }

    /// <summary>非敏感摘要。§6：审计不得出现令牌、密钥或 L4 明文。</summary>
    public string? Summary { get; init; }

    /// <summary>风险等级。§6 要求 refresh 重放这类事件产生高风险审计并告警。</summary>
    public AuditRisk Risk { get; init; } = AuditRisk.Normal;
}

public enum AuditRisk
{
    Normal,
    High,
}
