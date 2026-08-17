using Summer.BuildingBlocks.Application;
using Summer.BuildingBlocks.Domain;
using Summer.Modules.Identity.Domain;
using Xunit;

namespace Summer.Tests.Unit;

/// <summary>
/// Identity 领域层的纯逻辑测试，不触库。
/// 与集成测试的分工：这里管「规则本身对不对」，那里管「规则落到 PostgreSQL 上还成不成立」。
/// </summary>
public sealed class IdentityDomainTests
{
    private static readonly DateTimeOffset Now = new(2026, 5, 1, 12, 0, 0, TimeSpan.Zero);

    private static readonly SessionPolicy Policy = SessionPolicy.Create(
        accessTokenLifetime: TimeSpan.FromMinutes(15),
        refreshTokenLifetime: TimeSpan.FromHours(24),
        maxFailedAttempts: 3,
        lockoutDuration: TimeSpan.FromMinutes(10));

    private static UserAccount Account(
        string password = "Right-Answer-42", AccountStatus status = AccountStatus.Active,
        int failedCount = 0, DateTimeOffset? lockedUntil = null) => new()
        {
            Id = Guid.NewGuid(),
            LoginNameNormalized = "someone",
            PasswordHash = PasswordHasher.Hash(password),
            SessionVersion = 1,
            FailedCount = failedCount,
            LockedUntil = lockedUntil,
            Status = status,
            RowVersion = RowVersion.Initial,
        };

    // ---------------------------------------------------------------- 口令哈希

    [Fact]
    public void 口令哈希_相同口令每次产生不同哈希且都可验证()
    {
        string first = PasswordHasher.Hash("same-password");
        string second = PasswordHasher.Hash("same-password");

        // 盐随机，因此两次哈希不同；相同则说明没加盐，彩虹表可用
        Assert.NotEqual(first, second);
        Assert.True(PasswordHasher.Verify("same-password", first));
        Assert.True(PasswordHasher.Verify("same-password", second));
        Assert.False(PasswordHasher.Verify("other-password", first));
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-a-hash")]
    [InlineData("pbkdf2-sha512$abc$c2FsdA==$a2V5")]
    [InlineData("pbkdf2-sha512$0$c2FsdA==$a2V5")]
    [InlineData("md5$1$c2FsdA==$a2V5")]
    public void 口令哈希_格式异常一律判为不匹配而不抛出(string encoded)
    {
        // 抛异常会让攻击者从响应差异里区分「哈希损坏」与「口令错误」
        Assert.False(PasswordHasher.Verify("anything", encoded));
    }

    [Fact]
    public void 口令哈希_低迭代次数的存量哈希被标记为待升级()
    {
        string legacy = "pbkdf2-sha512$1000$c2FsdHNhbHRzYWx0c2E=$a2V5";

        Assert.True(PasswordHasher.NeedsUpgrade(legacy));
        Assert.False(PasswordHasher.NeedsUpgrade(PasswordHasher.Hash("fresh")));
    }

    // ---------------------------------------------------------------- 会话策略

    [Fact]
    public void 会话策略_refresh有效期不长于会话有效期时拒绝构造()
    {
        // 续期令牌比会话先过期，续期就永远不可能成功
        Assert.Throws<ArgumentOutOfRangeException>(() => SessionPolicy.Create(
            TimeSpan.FromMinutes(30), TimeSpan.FromMinutes(30), 3, TimeSpan.FromMinutes(5)));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void 会话策略_失败阈值非正时拒绝构造(int attempts)
        => Assert.Throws<ArgumentOutOfRangeException>(() => SessionPolicy.Create(
            TimeSpan.FromMinutes(15), TimeSpan.FromHours(1), attempts, TimeSpan.FromMinutes(5)));

    [Fact]
    public void 会话策略_环境变量缺失时报错并指名未冻结决策()
    {
        string? saved = Environment.GetEnvironmentVariable("SUMMER_IAM_ACCESS_TOKEN_SECONDS");
        Environment.SetEnvironmentVariable("SUMMER_IAM_ACCESS_TOKEN_SECONDS", null);

        try
        {
            InvalidOperationException error =
                Assert.Throws<InvalidOperationException>(SessionPolicy.FromEnvironment);

            // 错误信息必须点名 DEC-IAM-001，否则部署方不知道该找谁要这个值
            Assert.Contains("DEC-IAM-001", error.Message, StringComparison.Ordinal);
        }
        finally
        {
            Environment.SetEnvironmentVariable("SUMMER_IAM_ACCESS_TOKEN_SECONDS", saved);
        }
    }

    // ---------------------------------------------------------------- 账号状态迁移

    [Fact]
    public void 账号_口令正确时清零失败计数并记录登录时间()
    {
        UserAccount account = Account(failedCount: 2);

        (UserAccount next, LoginOutcome outcome) = account.Authenticate("Right-Answer-42", Now, Policy);

        Assert.Equal(LoginOutcome.Succeeded, outcome);
        Assert.Equal(0, next.FailedCount);
        Assert.Equal(Now, next.LastLoginAt);
        Assert.Equal(account.RowVersion.Next(), next.RowVersion);
    }

    [Fact]
    public void 账号_失败达阈值时转LOCKED并冻结锁定期()
    {
        UserAccount account = Account(failedCount: Policy.MaxFailedAttempts - 1);

        (UserAccount next, LoginOutcome outcome) = account.Authenticate("wrong", Now, Policy);

        Assert.Equal(LoginOutcome.BadCredential, outcome);
        Assert.Equal(AccountStatus.Locked, next.Status);
        Assert.Equal(Now + Policy.LockoutDuration, next.LockedUntil);
    }

    [Fact]
    public void 账号_锁定期内即使口令正确也不放行且状态不变()
    {
        UserAccount account = Account(
            status: AccountStatus.Locked, failedCount: 3, lockedUntil: Now + TimeSpan.FromMinutes(5));

        (UserAccount next, LoginOutcome outcome) = account.Authenticate("Right-Answer-42", Now, Policy);

        Assert.Equal(LoginOutcome.Locked, outcome);
        Assert.Equal(AccountStatus.Locked, next.Status);
        // 锁定期内的尝试不叠加计数，否则持续尝试可无限延长锁定
        Assert.Equal(3, next.FailedCount);
    }

    [Fact]
    public void 账号_锁定期结束且口令正确时恢复ACTIVE()
    {
        UserAccount account = Account(
            status: AccountStatus.Locked, failedCount: 3, lockedUntil: Now - TimeSpan.FromSeconds(1));

        (UserAccount next, LoginOutcome outcome) = account.Authenticate("Right-Answer-42", Now, Policy);

        Assert.Equal(LoginOutcome.Succeeded, outcome);
        Assert.Equal(AccountStatus.Active, next.Status);
        Assert.Null(next.LockedUntil);
    }

    [Fact]
    public void 账号_DISABLED不参与登录判定也不递增计数()
    {
        UserAccount account = Account(status: AccountStatus.Disabled);

        (UserAccount next, LoginOutcome outcome) = account.Authenticate("Right-Answer-42", Now, Policy);

        Assert.Equal(LoginOutcome.NotUsable, outcome);
        Assert.Equal(0, next.FailedCount);
        Assert.Equal(AccountStatus.Disabled, next.Status);
    }

    // ---------------------------------------------------------------- 会话受众冻结

    [Fact]
    public void 会话_PLATFORM携带Organization上下文时拒绝创建()
    {
        UserAccount account = Account();

        Assert.Throws<ArgumentException>(() => UserSession.Start(
            Guid.NewGuid(), account, Audience.Platform,
            organizationId: Guid.NewGuid(), organizationMemberId: Guid.NewGuid(),
            AuthStrength.Password, Now, Policy, Guid.NewGuid(), "SES-x"));
    }

    [Theory]
    [InlineData(Audience.Provider)]
    [InlineData(Audience.Enterprise)]
    public void 会话_非PLATFORM缺Organization上下文时拒绝创建(Audience audience)
    {
        UserAccount account = Account();

        Assert.Throws<ArgumentException>(() => UserSession.Start(
            Guid.NewGuid(), account, audience,
            organizationId: null, organizationMemberId: null,
            AuthStrength.Password, Now, Policy, Guid.NewGuid(), "SES-x"));
    }

    [Fact]
    public void 会话_创建时冻结账号安全版本快照()
    {
        UserAccount account = Account() with { SessionVersion = 7 };

        UserSession session = UserSession.Start(
            Guid.NewGuid(), account, Audience.Platform, null, null,
            AuthStrength.Password, Now, Policy, Guid.NewGuid(), "SES-x");

        Assert.Equal(7, session.SessionVersionSnapshot);
        Assert.Equal(SessionInvalidReason.None, session.Validate(7, Now));
        Assert.Equal(SessionInvalidReason.SecurityVersionChanged, session.Validate(8, Now));
    }

    [Fact]
    public void 会话_过期与终态分别报告不同失效原因()
    {
        UserAccount account = Account();
        UserSession session = UserSession.Start(
            Guid.NewGuid(), account, Audience.Platform, null, null,
            AuthStrength.Password, Now, Policy, Guid.NewGuid(), "SES-x");

        Assert.Equal(SessionInvalidReason.Expired,
            session.Validate(1, Now + Policy.AccessTokenLifetime));

        UserSession revoked = session.Revoke(Now, "TEST");
        Assert.Equal(SessionInvalidReason.Terminal, revoked.Validate(1, Now));
    }

    [Fact]
    public void 会话_对已撤销会话再次撤销不改写证据()
    {
        UserAccount account = Account();
        UserSession session = UserSession.Start(
            Guid.NewGuid(), account, Audience.Platform, null, null,
            AuthStrength.Password, Now, Policy, Guid.NewGuid(), "SES-x");

        UserSession first = session.Revoke(Now, "FIRST");
        UserSession second = first.Revoke(Now + TimeSpan.FromMinutes(5), "SECOND");

        // 终态不可恢复，也不该被二次撤销覆盖掉原始责任记录
        Assert.Equal(first.RevokedAt, second.RevokedAt);
        Assert.Equal("FIRST", second.RevokeReason);
        Assert.Equal(first.RowVersion, second.RowVersion);
    }

    // ---------------------------------------------------------------- 令牌

    [Fact]
    public void 令牌_过期或非ACTIVE即不可兑换()
    {
        SessionRefreshToken token = SessionRefreshToken.Issue(
            Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), 1, SecretHash.Of("secret"), Now, Policy);

        Assert.True(token.IsRedeemable(Now));
        Assert.False(token.IsRedeemable(Now + Policy.RefreshTokenLifetime));
        Assert.False(token.Consume(Now, Guid.NewGuid()).IsRedeemable(Now));
        Assert.False(token.Revoke(Now, "TEST").IsRedeemable(Now));
        Assert.False(token.MarkReused(Now, "TEST").IsRedeemable(Now));
    }

    [Fact]
    public void 令牌摘要_长度与字段字典的char64一致且随秘密变化()
    {
        string secret = SecretHash.NewSecret();
        string digest = SecretHash.Of(secret);

        Assert.Equal(64, digest.Length);
        Assert.Equal(digest, SecretHash.Of(secret));
        Assert.NotEqual(digest, SecretHash.Of(SecretHash.NewSecret()));
    }

    [Fact]
    public void 登录名规范化_大小写与空白不产生第二个账号()
    {
        // 唯一约束建在 login_name_normalized 上；规范化不一致会让唯一性被大小写绕过
        Assert.Equal(
            Modules.Identity.Application.AuthenticationService.NormalizeLoginName("  Ops.Admin  "),
            Modules.Identity.Application.AuthenticationService.NormalizeLoginName("ops.admin"));
    }
}
