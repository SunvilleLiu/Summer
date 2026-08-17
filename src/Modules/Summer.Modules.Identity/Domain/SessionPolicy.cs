using System.Globalization;

namespace Summer.Modules.Identity.Domain;

/// <summary>
/// 会话与登录保护的数值参数。
///
/// **这些数值属于 `DEC-IAM-001`（会话寿命、MFA、重新认证和设备策略），尚未冻结**，
/// 待 `GATE-LLD` 由 OWNER 决定（docs/03-交付治理与上线.md §5.1）。
///
/// 因此本类刻意不提供任何默认值：AGENTS.md §7 禁止对未冻结决策填入便利默认值。
/// 缺配置即启动失败，比悄悄用一个「看起来合理」的值安全——后者会让未冻结决策
/// 以实现细节的形式被静默冻结，而且没人知道它被冻结过。
///
/// 会话的**机制**（受众冻结、family 单次旋转、重放撤销、终态不可恢复）
/// 由 §3.3.1 与 §5.2.4 冻结，与本类的数值参数无关，故照常实现。
/// </summary>
public sealed record SessionPolicy
{
    private SessionPolicy(
        TimeSpan accessTokenLifetime,
        TimeSpan refreshTokenLifetime,
        int maxFailedAttempts,
        TimeSpan lockoutDuration)
    {
        AccessTokenLifetime = accessTokenLifetime;
        RefreshTokenLifetime = refreshTokenLifetime;
        MaxFailedAttempts = maxFailedAttempts;
        LockoutDuration = lockoutDuration;
    }

    /// <summary>会话（access 侧）有效期。DEC-IAM-001。</summary>
    public TimeSpan AccessTokenLifetime { get; }

    /// <summary>refresh token 单代有效期。DEC-IAM-001。</summary>
    public TimeSpan RefreshTokenLifetime { get; }

    /// <summary>触发锁定的连续失败次数。DEC-IAM-001。</summary>
    public int MaxFailedAttempts { get; }

    /// <summary>锁定时长。DEC-IAM-001。</summary>
    public TimeSpan LockoutDuration { get; }

    /// <summary>
    /// 显式构造。测试与非生产环境用它传入试验值——
    /// 试验值不是冻结值，两者的区别由调用点而不是由本类承担。
    /// </summary>
    public static SessionPolicy Create(
        TimeSpan accessTokenLifetime,
        TimeSpan refreshTokenLifetime,
        int maxFailedAttempts,
        TimeSpan lockoutDuration)
    {
        if (accessTokenLifetime <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(accessTokenLifetime), accessTokenLifetime, "会话有效期必须为正");
        }

        if (refreshTokenLifetime <= accessTokenLifetime)
        {
            throw new ArgumentOutOfRangeException(nameof(refreshTokenLifetime), refreshTokenLifetime,
                "refresh token 有效期必须长于会话有效期，否则续期无意义");
        }

        if (maxFailedAttempts <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxFailedAttempts), maxFailedAttempts, "失败阈值必须为正");
        }

        if (lockoutDuration <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(lockoutDuration), lockoutDuration, "锁定时长必须为正");
        }

        return new SessionPolicy(accessTokenLifetime, refreshTokenLifetime, maxFailedAttempts, lockoutDuration);
    }

    /// <summary>
    /// 从环境变量读取。四项全部必填，任一缺失即抛出并指名 DEC-IAM-001。
    /// </summary>
    public static SessionPolicy FromEnvironment()
        => Create(
            ReadTimeSpan("SUMMER_IAM_ACCESS_TOKEN_SECONDS"),
            ReadTimeSpan("SUMMER_IAM_REFRESH_TOKEN_SECONDS"),
            ReadInt32("SUMMER_IAM_MAX_FAILED_ATTEMPTS"),
            ReadTimeSpan("SUMMER_IAM_LOCKOUT_SECONDS"));

    private static TimeSpan ReadTimeSpan(string variable)
        => TimeSpan.FromSeconds(ReadInt32(variable));

    private static int ReadInt32(string variable)
    {
        string? raw = Environment.GetEnvironmentVariable(variable);
        if (string.IsNullOrWhiteSpace(raw))
        {
            throw new InvalidOperationException(
                $"未设置 {variable}。该参数属于未冻结决策 DEC-IAM-001（会话寿命、MFA、重新认证和设备策略），" +
                "在 GATE-LLD 冻结前必须由部署方显式给出，实现方不得代填默认值。");
        }

        if (!int.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out int value))
        {
            throw new InvalidOperationException($"{variable} 的值 “{raw}” 不是非负整数");
        }

        return value;
    }
}
