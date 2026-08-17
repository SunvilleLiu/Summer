namespace Summer.Modules.Identity.Domain;

/// <summary>
/// 账号状态，STATE-IAM-001（docs/04-系统设计.md §3.3.1）：
/// ACTIVE → LOCKED/DISABLED；LOCKED 只能在锁定期结束且风险重校验通过后恢复，
/// DISABLED 只能经受控恢复流程回到 ACTIVE。
/// </summary>
public enum AccountStatus
{
    Active,
    Locked,
    Disabled,
}

/// <summary>
/// 会话状态，STATE-IAM-001：ACTIVE → EXPIRED/REVOKED，终态不可恢复。
/// </summary>
public enum SessionStatus
{
    Active,
    Expired,
    Revoked,
}

/// <summary>
/// refresh token 状态（§5.2.4）。
/// REUSED 不是普通终态：它是「已消费代被重放」的证据，触发 family 与 session 全撤销。
/// </summary>
public enum RefreshTokenStatus
{
    Active,
    Consumed,
    Revoked,
    Expired,
    Reused,
}

/// <summary>认证强度（§5.2.4 auth_strength）。</summary>
public enum AuthStrength
{
    Password,
    Mfa,
    Reauth,
}

/// <summary>状态与其入库稳定代码的互转。§1.8.1：入库的是代码，不是显示名。</summary>
public static class IdentityCodes
{
    public static string ToCode(AccountStatus value) => value switch
    {
        AccountStatus.Active => "ACTIVE",
        AccountStatus.Locked => "LOCKED",
        AccountStatus.Disabled => "DISABLED",
        _ => throw new ArgumentOutOfRangeException(nameof(value), value, "未知账号状态"),
    };

    public static AccountStatus ParseAccountStatus(string code) => code switch
    {
        "ACTIVE" => AccountStatus.Active,
        "LOCKED" => AccountStatus.Locked,
        "DISABLED" => AccountStatus.Disabled,
        _ => throw new ArgumentOutOfRangeException(nameof(code), code, "未知账号状态代码"),
    };

    public static string ToCode(SessionStatus value) => value switch
    {
        SessionStatus.Active => "ACTIVE",
        SessionStatus.Expired => "EXPIRED",
        SessionStatus.Revoked => "REVOKED",
        _ => throw new ArgumentOutOfRangeException(nameof(value), value, "未知会话状态"),
    };

    public static SessionStatus ParseSessionStatus(string code) => code switch
    {
        "ACTIVE" => SessionStatus.Active,
        "EXPIRED" => SessionStatus.Expired,
        "REVOKED" => SessionStatus.Revoked,
        _ => throw new ArgumentOutOfRangeException(nameof(code), code, "未知会话状态代码"),
    };

    public static string ToCode(RefreshTokenStatus value) => value switch
    {
        RefreshTokenStatus.Active => "ACTIVE",
        RefreshTokenStatus.Consumed => "CONSUMED",
        RefreshTokenStatus.Revoked => "REVOKED",
        RefreshTokenStatus.Expired => "EXPIRED",
        RefreshTokenStatus.Reused => "REUSED",
        _ => throw new ArgumentOutOfRangeException(nameof(value), value, "未知令牌状态"),
    };

    public static RefreshTokenStatus ParseRefreshTokenStatus(string code) => code switch
    {
        "ACTIVE" => RefreshTokenStatus.Active,
        "CONSUMED" => RefreshTokenStatus.Consumed,
        "REVOKED" => RefreshTokenStatus.Revoked,
        "EXPIRED" => RefreshTokenStatus.Expired,
        "REUSED" => RefreshTokenStatus.Reused,
        _ => throw new ArgumentOutOfRangeException(nameof(code), code, "未知令牌状态代码"),
    };

    public static string ToCode(AuthStrength value) => value switch
    {
        AuthStrength.Password => "PASSWORD",
        AuthStrength.Mfa => "MFA",
        AuthStrength.Reauth => "REAUTH",
        _ => throw new ArgumentOutOfRangeException(nameof(value), value, "未知认证强度"),
    };

    public static AuthStrength ParseAuthStrength(string code) => code switch
    {
        "PASSWORD" => AuthStrength.Password,
        "MFA" => AuthStrength.Mfa,
        "REAUTH" => AuthStrength.Reauth,
        _ => throw new ArgumentOutOfRangeException(nameof(code), code, "未知认证强度代码"),
    };
}
