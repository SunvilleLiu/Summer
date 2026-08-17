using Summer.BuildingBlocks.Application;
using Summer.BuildingBlocks.Domain;

namespace Summer.Modules.Identity.Domain;

/// <summary>第一因素认证的内部判定结果。对外一律折叠为统一失败响应（§7.2.5）。</summary>
public enum LoginOutcome
{
    /// <summary>口令正确且账号可用。</summary>
    Succeeded,

    /// <summary>口令错误。</summary>
    BadCredential,

    /// <summary>账号处于锁定期内。</summary>
    Locked,

    /// <summary>账号 DISABLED，或 LOCKED 且未到锁定期结束。</summary>
    NotUsable,
}

/// <summary>
/// ENT-IAM-001 <c>user_account</c> 聚合（docs/04-系统设计.md §5.2.2）。
///
/// 做成不可变记录、由方法返回下一状态，是为了让 STATE-IAM-001 的迁移
/// 能以纯函数方式测试，不必先落库再查库。
/// </summary>
public sealed record UserAccount
{
    public required Guid Id { get; init; }

    public required string LoginNameNormalized { get; init; }

    public required string PasswordHash { get; init; }

    /// <summary>账号安全版本。会话持有其快照，不等即失效（§7.2.4 第 8 条）。</summary>
    public required long SessionVersion { get; init; }

    public required int FailedCount { get; init; }

    public DateTimeOffset? LockedUntil { get; init; }

    public DateTimeOffset? LastLoginAt { get; init; }

    public DateTimeOffset? PasswordChangedAt { get; init; }

    public required AccountStatus Status { get; init; }

    public required RowVersion RowVersion { get; init; }

    /// <summary>
    /// 执行第一因素认证并返回账号的下一状态。
    ///
    /// 无论成败都要**先**做口令校验：只有 DISABLED 能提前返回。
    /// 若对锁定账号跳过 PBKDF2，响应时间差会把账号状态泄露给攻击者，
    /// 这与 §7.2.5 的反枚举要求相抵触。
    /// </summary>
    public (UserAccount Next, LoginOutcome Outcome) Authenticate(
        string password, DateTimeOffset now, SessionPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);

        if (Status is AccountStatus.Disabled)
        {
            // DISABLED 只能经受控恢复流程回到 ACTIVE（§3.3.1），登录路径不参与恢复，
            // 也不递增失败计数——否则可以靠登录尝试无限延长他人锁定。
            return (this, LoginOutcome.NotUsable);
        }

        bool passwordMatches = PasswordHasher.Verify(password, PasswordHash);
        bool withinLockout = LockedUntil is { } until && now < until;

        if (withinLockout)
        {
            return (this, LoginOutcome.Locked);
        }

        if (!passwordMatches)
        {
            return (RegisterFailure(now, policy), LoginOutcome.BadCredential);
        }

        // 锁定期已过且口令正确：这次成功的口令校验就是 §3.3.1 所称的重校验最小形式。
        // 「风险重校验」的完整定义（设备、IP、风险信号）属未冻结的 DEC-IAM-001，
        // 待冻结后在此处扩展，而不是现在替 OWNER 猜一个风控模型。
        return (RegisterSuccess(now), LoginOutcome.Succeeded);
    }

    /// <summary>失败一次：递增计数，达阈值则转 LOCKED 并冻结锁定期。</summary>
    public UserAccount RegisterFailure(DateTimeOffset now, SessionPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);

        int failed = FailedCount + 1;
        bool shouldLock = failed >= policy.MaxFailedAttempts;

        return this with
        {
            FailedCount = failed,
            Status = shouldLock ? AccountStatus.Locked : Status,
            LockedUntil = shouldLock ? now + policy.LockoutDuration : LockedUntil,
            RowVersion = RowVersion.Next(),
        };
    }

    /// <summary>成功一次：清零计数、解除锁定期、回到 ACTIVE 并记录登录时间。</summary>
    public UserAccount RegisterSuccess(DateTimeOffset now)
        => this with
        {
            FailedCount = 0,
            LockedUntil = null,
            Status = AccountStatus.Active,
            LastLoginAt = now,
            RowVersion = RowVersion.Next(),
        };

    /// <summary>
    /// 递增安全版本。改密、停用、风险处置与 refresh 重放都要调用（§5.2.2、§5.2.4）。
    /// 递增本身不撤销会话行，撤销由调用方在同一事务内完成。
    /// </summary>
    public UserAccount BumpSessionVersion()
        => this with { SessionVersion = SessionVersion + 1, RowVersion = RowVersion.Next() };
}
