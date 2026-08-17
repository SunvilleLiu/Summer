namespace Summer.BuildingBlocks.Application;

/// <summary>
/// 错误码目录，前缀与 HTTP 映射冻结于 docs/04-系统设计.md §8.10。
///
/// 该节给的是「稳定示例」而非完整目录，因此实现期需要在冻结前缀下补具体码。
/// 补充的码集中登记在本类 <see cref="Introduced"/> 中，等待纳入 §8.10 正式目录，
/// 不散落在各模块里——散落等于事实上的目录分叉。
/// </summary>
public static class ErrorCodes
{
    // ---- §8.10 已明示的稳定示例 ----

    /// <summary>令牌失效。§8.10 明示。</summary>
    public const string AuthTokenInvalid = "AUTH-TOKEN-001";

    /// <summary>受众错误。§8.10 明示。</summary>
    public const string AudienceMismatch = "AUD-MISMATCH-001";

    /// <summary>禁止客户端提交作用域。§8.10 明示，对应 §5.1.2 末段与 §4.6。</summary>
    public const string ForbiddenClientScope = "VALID-FORBIDDEN-001";

    /// <summary>同键异摘要。§8.10 明示。</summary>
    public const string IdempotencyMismatch = "DUP-IDEMPOTENCY-002";

    /// <summary>版本变化。§8.10 明示。</summary>
    public const string ConcurrencyVersion = "CONC-VERSION-001";

    /// <summary>状态不允许。§8.10 明示。</summary>
    public const string BusinessState = "BIZ-STATE-001";

    /// <summary>能力无效。§8.10 明示。</summary>
    public const string OrganizationCapability = "ORG-CAPABILITY-001";

    // ---- 实现期在冻结前缀下补充的码 ----

    /// <summary>
    /// 第一因素认证失败的统一响应。
    /// §7.2.5 要求登录执行反枚举与统一失败响应：账号不存在、密码错误、账号被锁
    /// 三种情形对外必须不可区分，因此共用一个码，差异只进审计。
    /// </summary>
    public const string AuthCredentialRejected = "AUTH-CREDENTIAL-001";

    /// <summary>
    /// refresh token 家族检测到重放。
    /// §5.2.4：已消费代再次出现即撤销整个 family 与 session 并递增账号安全版本。
    /// </summary>
    public const string AuthRefreshReuse = "AUTH-REFRESH-001";

    /// <summary>会话已终态（EXPIRED/REVOKED）。§3.3.1：终态不可恢复。</summary>
    public const string AuthSessionTerminal = "AUTH-SESSION-001";

    /// <summary>
    /// 本类在 §8.10 稳定示例之外补充的码，供治理侧复核后纳入正式目录。
    /// 键是错误码，值是补充理由与依据章节。
    /// </summary>
    public static IReadOnlyDictionary<string, string> Introduced { get; } =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [AuthCredentialRejected] = "§7.2.5 统一失败响应与反枚举，登录三种失败情形对外不可区分",
            [AuthRefreshReuse] = "§5.2.4 refresh token family 重放检测",
            [AuthSessionTerminal] = "§3.3.1 会话终态不可恢复",
        };
}
