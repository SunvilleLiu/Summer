namespace Summer.BuildingBlocks.Domain;

/// <summary>
/// 三类互斥受众，见 docs/04-系统设计.md §4.2.3。
/// 一个 user_session 只能冻结一种；切换受众必须新建会话，不得原地覆盖令牌声明（§3.3.1）。
/// </summary>
public enum Audience
{
    /// <summary>平台控制台。不得携带 Organization/Workspace 业务上下文。</summary>
    Platform,

    /// <summary>服务机构工作端。Organization 须具备 ACTIVE PROVIDE_SERVICE。</summary>
    Provider,

    /// <summary>客户企业门户。Organization 须具备 ACTIVE RECEIVE_SERVICE。</summary>
    Enterprise,
}

/// <summary>
/// 受众与其稳定门户代码之间的映射（§3.3.1 表）。
/// 稳定代码入库与入事件，中文显示名不参与判断（§1.8.1）。
/// </summary>
public static class AudienceCodes
{
    public const string Platform = "PLATFORM";
    public const string Provider = "PROVIDER";
    public const string Enterprise = "ENTERPRISE";

    public const string PlatformPortal = "PLATFORM_CONSOLE";
    public const string ProviderPortal = "PROVIDER_PORTAL";
    public const string EnterprisePortal = "ENTERPRISE_PORTAL";

    public static string ToCode(Audience audience) => audience switch
    {
        Audience.Platform => Platform,
        Audience.Provider => Provider,
        Audience.Enterprise => Enterprise,
        _ => throw new ArgumentOutOfRangeException(nameof(audience), audience, "未知 Audience"),
    };

    public static string ToPortalCode(Audience audience) => audience switch
    {
        Audience.Platform => PlatformPortal,
        Audience.Provider => ProviderPortal,
        Audience.Enterprise => EnterprisePortal,
        _ => throw new ArgumentOutOfRangeException(nameof(audience), audience, "未知 Audience"),
    };

    public static Audience Parse(string code) => code switch
    {
        Platform => Audience.Platform,
        Provider => Audience.Provider,
        Enterprise => Audience.Enterprise,
        _ => throw new ArgumentOutOfRangeException(nameof(code), code, "未知 Audience 代码"),
    };

    /// <summary>
    /// §4.2.3 / §5.2.4：PLATFORM 会话不得有 Organization；PROVIDER/ENTERPRISE 必填。
    /// </summary>
    public static bool RequiresOrganization(Audience audience) => audience is not Audience.Platform;
}
