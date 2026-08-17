namespace Summer.Modules.Identity.Contracts;

/// <summary>
/// Identity 对 Organization 的**跨模块只读查询契约**。
///
/// §5.2.4 要求 PROVIDER 会话的 Organization 必须具备 ACTIVE <c>PROVIDE_SERVICE</c>，
/// ENTERPRISE 同理校验 <c>RECEIVE_SERVICE</c>，且 <c>organization_member_id</c>
/// 必须属于该 organization/user。这些事实全部由 DOM-ORG-001 拥有，
/// 而 §4.3.1 规定模块只写本模块拥有的表、跨模块读取走公开查询契约——
/// 所以 Identity 只能提出问题，不能自己查 organization schema。
///
/// **本接口是新增的跨模块接口，尚未与 DOM-ORG-001 的负责方确认**（AGENTS.md §4）。
/// 在其获得实现前，PROVIDER/ENTERPRISE 会话按「未知失败关闭」处理，
/// 不得退化为「查不到就放行」。
/// </summary>
public interface IOrganizationContextVerifier
{
    /// <summary>
    /// 校验某账号能否以指定成员身份、在指定 Organization 下建立该受众的会话。
    /// 实现方必须一并校验：成员关系 ACTIVE、成员属于该 Organization 与该账号、
    /// Organization 非 CLOSED/SUSPENDED、且具备受众对应的 ACTIVE capability。
    /// </summary>
    Task<OrganizationContextVerdict> VerifyAsync(
        Guid userAccountId,
        Guid organizationId,
        Guid organizationMemberId,
        string requiredCapabilityCode,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// 校验结论。失败原因用稳定代码表达，且对外响应必须统一，
/// 不得让调用方据此区分「Organization 不存在」与「无权限」（§7.2.5 反枚举）。
/// </summary>
public sealed record OrganizationContextVerdict(bool Allowed, string? ReasonCode)
{
    public static OrganizationContextVerdict Allow() => new(true, null);

    public static OrganizationContextVerdict Deny(string reasonCode) => new(false, reasonCode);
}

/// <summary>受众所要求的 Organization 能力代码（§4.2.2）。</summary>
public static class CapabilityCodes
{
    public const string ProvideService = "PROVIDE_SERVICE";
    public const string ReceiveService = "RECEIVE_SERVICE";
}
