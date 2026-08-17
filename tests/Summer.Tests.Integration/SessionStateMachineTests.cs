using Summer.BuildingBlocks.Application;
using Summer.BuildingBlocks.Domain;
using Summer.Modules.Identity.Application;
using Summer.Modules.Identity.Contracts;
using Summer.Modules.Identity.Domain;
using Xunit;

namespace Summer.Tests.Integration;

/// <summary>
/// STATE-IAM-001（docs/04-系统设计.md §3.3.1）的状态机测试。
///
/// 覆盖 §3.15 要求的七类场景，每个测试方法名前缀标出所属类别：
/// 主路径 / 分支 / 非法迁移 / 重复命令 / 并发冲突 / 权限失效 / 终态保护。
///
/// 未覆盖：MFA 因子与身份挑战两条子状态机（§3.3.1），
/// 它们的表与实现随 MFA 纵切交付，本次范围内无代码可测。
/// </summary>
[Collection(nameof(IamDatabaseCollection))]
public sealed class SessionStateMachineTests(IamDatabaseFixture fixture)
{
    private static readonly DateTimeOffset Origin = new(2026, 1, 5, 8, 0, 0, TimeSpan.Zero);

    private static int _sequence;

    private static string NextLoginName(string prefix)
        => $"{prefix}-{Interlocked.Increment(ref _sequence)}-{Guid.NewGuid():N}"[..40].ToLowerInvariant();

    private (AuthenticationService Service, RecordingAuditSink Audit, MutableClock Clock) NewService(
        IOrganizationContextVerifier? verifier = null)
    {
        var audit = new RecordingAuditSink();
        var clock = new MutableClock(Origin);
        var service = new AuthenticationService(
            fixture.Options, IamDatabaseFixture.TestPolicy, clock, audit, verifier);
        return (service, audit, clock);
    }

    private static LoginCommand PlatformLogin(string loginName, string password) => new()
    {
        LoginName = loginName,
        Password = password,
        Audience = Audience.Platform,
        IdempotencyKey = Guid.NewGuid().ToString("N"),
        CorrelationId = Guid.NewGuid().ToString("N"),
    };

    // ============================================================ 1. 合法主路径

    [Fact]
    public async Task 主路径_登录建立ACTIVE会话并签发第一代令牌()
    {
        (Guid accountId, string login, string password) = await fixture.SeedAccountAsync(NextLoginName("mainpath"));
        (AuthenticationService service, RecordingAuditSink audit, _) = NewService();

        Result<SessionIssued> result = await service.LoginAsync(PlatformLogin(login, password));

        Assert.True(result.IsSuccess);
        SessionIssued issued = result.Value;

        UserSession session = await fixture.GetSessionAsync(issued.SessionId);
        Assert.Equal(SessionStatus.Active, session.Status);
        Assert.Equal(Audience.Platform, session.Audience);
        Assert.Equal(accountId, session.UserAccountId);
        Assert.Equal(Origin + IamDatabaseFixture.TestPolicy.AccessTokenLifetime, session.ExpiresAt);

        // §4.2.3：PLATFORM 会话不得携带 Organization 上下文
        Assert.Null(session.OrganizationId);
        Assert.Null(session.OrganizationMemberId);

        SessionRefreshToken token = await fixture.GetTokenBySecretAsync(issued.RefreshToken);
        Assert.Equal(1, token.Generation);
        Assert.Equal(RefreshTokenStatus.Active, token.Status);

        Assert.Single(audit.OfType("iam.session.started"));
    }

    [Fact]
    public async Task 主路径_刷新消费当代并签发下一代()
    {
        (_, string login, string password) = await fixture.SeedAccountAsync(NextLoginName("rotate"));
        (AuthenticationService service, RecordingAuditSink audit, MutableClock clock) = NewService();

        SessionIssued first = (await service.LoginAsync(PlatformLogin(login, password))).Value;
        clock.Advance(TimeSpan.FromMinutes(1));

        Result<SessionIssued> refreshed = await service.RefreshAsync(new RefreshCommand
        {
            RefreshToken = first.RefreshToken,
            IdempotencyKey = Guid.NewGuid().ToString("N"),
        });

        Assert.True(refreshed.IsSuccess);
        Assert.NotEqual(first.RefreshToken, refreshed.Value.RefreshToken);

        SessionRefreshToken consumed = await fixture.GetTokenBySecretAsync(first.RefreshToken);
        SessionRefreshToken next = await fixture.GetTokenBySecretAsync(refreshed.Value.RefreshToken);

        Assert.Equal(RefreshTokenStatus.Consumed, consumed.Status);
        Assert.Equal(next.Id, consumed.ReplacedByTokenId);
        Assert.Equal(2, next.Generation);
        Assert.Equal(RefreshTokenStatus.Active, next.Status);
        Assert.Equal(consumed.FamilyId, next.FamilyId);

        // 会话有效期以刷新时刻为基准重算
        UserSession session = await fixture.GetSessionAsync(first.SessionId);
        Assert.Equal(clock.UtcNow + IamDatabaseFixture.TestPolicy.AccessTokenLifetime, session.ExpiresAt);

        Assert.Single(audit.OfType("iam.session.refreshed"));
    }

    [Fact]
    public async Task 主路径_登出撤销会话并收口family()
    {
        (_, string login, string password) = await fixture.SeedAccountAsync(NextLoginName("logout"));
        (AuthenticationService service, RecordingAuditSink audit, MutableClock clock) = NewService();

        SessionIssued issued = (await service.LoginAsync(PlatformLogin(login, password))).Value;
        clock.Advance(TimeSpan.FromMinutes(1));

        Result<bool> logout = await service.LogoutAsync(new LogoutCommand
        {
            SessionId = issued.SessionId,
            IdempotencyKey = Guid.NewGuid().ToString("N"),
        });

        Assert.True(logout.IsSuccess);

        UserSession session = await fixture.GetSessionAsync(issued.SessionId);
        Assert.Equal(SessionStatus.Revoked, session.Status);
        Assert.Equal(clock.UtcNow, session.RevokedAt);
        Assert.NotNull(session.RevokeReason);

        IReadOnlyList<(int Generation, RefreshTokenStatus Status)> family =
            await fixture.GetFamilyAsync(session.RefreshFamilyId);
        Assert.All(family, row => Assert.Equal(RefreshTokenStatus.Revoked, row.Status));

        Assert.Single(audit.OfType("iam.session.revoked"));
    }

    // ============================================================ 2. 所有分支

    [Fact]
    public async Task 分支_口令错误递增失败计数且不建立会话()
    {
        (Guid accountId, string login, _) = await fixture.SeedAccountAsync(NextLoginName("badpwd"));
        (AuthenticationService service, _, _) = NewService();

        Result<SessionIssued> result = await service.LoginAsync(PlatformLogin(login, "wrong-password"));

        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCodes.AuthCredentialRejected, result.Error!.Code);

        UserAccount account = await fixture.GetAccountAsync(accountId);
        Assert.Equal(1, account.FailedCount);
        Assert.Equal(AccountStatus.Active, account.Status);
    }

    [Fact]
    public async Task 分支_连续失败达阈值转LOCKED并冻结锁定期()
    {
        (Guid accountId, string login, string password) = await fixture.SeedAccountAsync(NextLoginName("lockout"));
        (AuthenticationService service, _, MutableClock clock) = NewService();

        for (int i = 0; i < IamDatabaseFixture.TestPolicy.MaxFailedAttempts; i++)
        {
            await service.LoginAsync(PlatformLogin(login, "wrong-password"));
        }

        UserAccount locked = await fixture.GetAccountAsync(accountId);
        Assert.Equal(AccountStatus.Locked, locked.Status);
        Assert.Equal(Origin + IamDatabaseFixture.TestPolicy.LockoutDuration, locked.LockedUntil);

        // 锁定期内即使口令正确也不放行
        Result<SessionIssued> duringLockout = await service.LoginAsync(PlatformLogin(login, password));
        Assert.False(duringLockout.IsSuccess);
        Assert.Equal(ErrorCodes.AuthCredentialRejected, duringLockout.Error!.Code);

        // §3.3.1：锁定期结束且重校验通过后方可恢复
        clock.Advance(IamDatabaseFixture.TestPolicy.LockoutDuration + TimeSpan.FromMinutes(1));
        Result<SessionIssued> afterLockout = await service.LoginAsync(PlatformLogin(login, password));

        Assert.True(afterLockout.IsSuccess);
        UserAccount recovered = await fixture.GetAccountAsync(accountId);
        Assert.Equal(AccountStatus.Active, recovered.Status);
        Assert.Equal(0, recovered.FailedCount);
        Assert.Null(recovered.LockedUntil);
    }

    [Fact]
    public async Task 分支_DISABLED账号登录失败且不递增失败计数()
    {
        (Guid accountId, string login, string password) =
            await fixture.SeedAccountAsync(NextLoginName("disabled"), status: AccountStatus.Disabled);
        (AuthenticationService service, _, _) = NewService();

        Result<SessionIssued> result = await service.LoginAsync(PlatformLogin(login, password));

        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCodes.AuthCredentialRejected, result.Error!.Code);

        // DISABLED 只能经受控恢复流程回到 ACTIVE（§3.3.1）；
        // 若此处递增计数，任何人都能靠登录尝试给他人账号叠加锁定。
        UserAccount account = await fixture.GetAccountAsync(accountId);
        Assert.Equal(0, account.FailedCount);
        Assert.Equal(AccountStatus.Disabled, account.Status);
    }

    [Fact]
    public async Task 分支_登录名不存在返回与口令错误相同的响应()
    {
        (AuthenticationService service, _, _) = NewService();

        Result<SessionIssued> result = await service.LoginAsync(
            PlatformLogin(NextLoginName("ghost"), "any-password"));

        Assert.False(result.IsSuccess);
        // §7.2.5 反枚举：与「口令错误」同码同文案，调用方无法区分账号是否存在
        Assert.Equal(ErrorCodes.AuthCredentialRejected, result.Error!.Code);
        Assert.Equal("登录名或口令不正确", result.Error.Message);
    }

    // ============================================================ 3. 非法迁移

    [Fact]
    public async Task 非法迁移_登出后不得再刷新()
    {
        (_, string login, string password) = await fixture.SeedAccountAsync(NextLoginName("afterlogout"));
        (AuthenticationService service, _, _) = NewService();

        SessionIssued issued = (await service.LoginAsync(PlatformLogin(login, password))).Value;
        await service.LogoutAsync(new LogoutCommand
        {
            SessionId = issued.SessionId,
            IdempotencyKey = Guid.NewGuid().ToString("N"),
        });

        Result<SessionIssued> refreshed = await service.RefreshAsync(new RefreshCommand
        {
            RefreshToken = issued.RefreshToken,
            IdempotencyKey = Guid.NewGuid().ToString("N"),
        });

        // 登出已把 family 内 ACTIVE 各代置 REVOKED，该代不可兑换
        Assert.False(refreshed.IsSuccess);
        Assert.Equal(ErrorCodes.AuthTokenInvalid, refreshed.Error!.Code);
    }

    [Fact]
    public async Task 非法迁移_会话过期后不得刷新()
    {
        (_, string login, string password) = await fixture.SeedAccountAsync(NextLoginName("expired"));
        (AuthenticationService service, _, MutableClock clock) = NewService();

        SessionIssued issued = (await service.LoginAsync(PlatformLogin(login, password))).Value;

        // 越过会话有效期，但仍在 refresh token 有效期内：
        // 会话本身失效即不得续期，否则过期会话可被无限续命。
        clock.Advance(IamDatabaseFixture.TestPolicy.AccessTokenLifetime + TimeSpan.FromMinutes(1));

        Result<SessionIssued> refreshed = await service.RefreshAsync(new RefreshCommand
        {
            RefreshToken = issued.RefreshToken,
            IdempotencyKey = Guid.NewGuid().ToString("N"),
        });

        Assert.False(refreshed.IsSuccess);
        Assert.Equal(ErrorCodes.AuthSessionTerminal, refreshed.Error!.Code);
    }

    [Fact]
    public async Task 非法迁移_未知令牌不得建立会话()
    {
        (AuthenticationService service, _, _) = NewService();

        Result<SessionIssued> refreshed = await service.RefreshAsync(new RefreshCommand
        {
            RefreshToken = SecretHash.NewSecret(),
            IdempotencyKey = Guid.NewGuid().ToString("N"),
        });

        Assert.False(refreshed.IsSuccess);
        Assert.Equal(ErrorCodes.AuthTokenInvalid, refreshed.Error!.Code);
    }

    // ============================================================ 4. 重复命令

    [Fact]
    public async Task 重复命令_同一令牌第二次使用触发重放处置()
    {
        (Guid accountId, string login, string password) = await fixture.SeedAccountAsync(NextLoginName("replay"));
        (AuthenticationService service, RecordingAuditSink audit, MutableClock clock) = NewService();

        SessionIssued first = (await service.LoginAsync(PlatformLogin(login, password))).Value;
        clock.Advance(TimeSpan.FromMinutes(1));

        SessionIssued second = (await service.RefreshAsync(new RefreshCommand
        {
            RefreshToken = first.RefreshToken,
            IdempotencyKey = Guid.NewGuid().ToString("N"),
        })).Value;

        long versionBefore = (await fixture.GetAccountAsync(accountId)).SessionVersion;
        clock.Advance(TimeSpan.FromMinutes(1));

        // 重放第一代（已 CONSUMED）
        Result<SessionIssued> replay = await service.RefreshAsync(new RefreshCommand
        {
            RefreshToken = first.RefreshToken,
            IdempotencyKey = Guid.NewGuid().ToString("N"),
        });

        Assert.False(replay.IsSuccess);
        Assert.Equal(ErrorCodes.AuthRefreshReuse, replay.Error!.Code);

        // §5.2.4 的四项处置逐一验证
        SessionRefreshToken replayed = await fixture.GetTokenBySecretAsync(first.RefreshToken);
        Assert.Equal(RefreshTokenStatus.Reused, replayed.Status);

        UserSession session = await fixture.GetSessionAsync(first.SessionId);
        Assert.Equal(SessionStatus.Revoked, session.Status);

        IReadOnlyList<(int Generation, RefreshTokenStatus Status)> family =
            await fixture.GetFamilyAsync(session.RefreshFamilyId);
        Assert.DoesNotContain(family, row => row.Status == RefreshTokenStatus.Active);

        UserAccount account = await fixture.GetAccountAsync(accountId);
        Assert.Equal(versionBefore + 1, account.SessionVersion);

        AuditEntry alert = Assert.Single(audit.OfType("iam.session.refresh_reuse_detected"));
        Assert.Equal(AuditRisk.High, alert.Risk);

        // 被撤销 family 的最新一代也随之失效
        Result<SessionIssued> afterReuse = await service.RefreshAsync(new RefreshCommand
        {
            RefreshToken = second.RefreshToken,
            IdempotencyKey = Guid.NewGuid().ToString("N"),
        });
        Assert.False(afterReuse.IsSuccess);
    }

    [Fact]
    public async Task 重复命令_重复登出幂等且不改写撤销证据()
    {
        (_, string login, string password) = await fixture.SeedAccountAsync(NextLoginName("dblogout"));
        (AuthenticationService service, _, MutableClock clock) = NewService();

        SessionIssued issued = (await service.LoginAsync(PlatformLogin(login, password))).Value;

        await service.LogoutAsync(new LogoutCommand
        {
            SessionId = issued.SessionId,
            IdempotencyKey = Guid.NewGuid().ToString("N"),
        });
        UserSession afterFirst = await fixture.GetSessionAsync(issued.SessionId);

        clock.Advance(TimeSpan.FromMinutes(3));
        Result<bool> secondLogout = await service.LogoutAsync(new LogoutCommand
        {
            SessionId = issued.SessionId,
            IdempotencyKey = Guid.NewGuid().ToString("N"),
        });

        Assert.True(secondLogout.IsSuccess);

        UserSession afterSecond = await fixture.GetSessionAsync(issued.SessionId);
        // 撤销时间与原因是责任证据，第二次登出不得覆盖
        Assert.Equal(afterFirst.RevokedAt, afterSecond.RevokedAt);
        Assert.Equal(afterFirst.RowVersion, afterSecond.RowVersion);
    }

    // ============================================================ 5. 并发版本冲突

    [Fact]
    public async Task 并发冲突_同一令牌并发刷新不产生分叉()
    {
        (_, string login, string password) = await fixture.SeedAccountAsync(NextLoginName("concurrent"));
        (AuthenticationService service, _, MutableClock clock) = NewService();

        SessionIssued issued = (await service.LoginAsync(PlatformLogin(login, password))).Value;
        clock.Advance(TimeSpan.FromMinutes(1));

        RefreshCommand Command() => new()
        {
            RefreshToken = issued.RefreshToken,
            IdempotencyKey = Guid.NewGuid().ToString("N"),
        };

        Task<Result<SessionIssued>> left = service.RefreshAsync(Command());
        Task<Result<SessionIssued>> right = service.RefreshAsync(Command());
        Result<SessionIssued>[] results = await Task.WhenAll(left, right);

        // 行锁串行化两个请求：先到者旋转成功，后到者读到 CONSUMED 判为重放。
        // §5.2.4 「并发刷新不得产生分叉」在此体现为——family 内绝不会出现两个 ACTIVE 代。
        Assert.Equal(1, results.Count(r => r.IsSuccess));
        Result<SessionIssued> loser = results.Single(r => !r.IsSuccess);
        Assert.Equal(ErrorCodes.AuthRefreshReuse, loser.Error!.Code);

        UserSession session = await fixture.GetSessionAsync(issued.SessionId);
        IReadOnlyList<(int Generation, RefreshTokenStatus Status)> family =
            await fixture.GetFamilyAsync(session.RefreshFamilyId);

        Assert.DoesNotContain(family, row => row.Status == RefreshTokenStatus.Active);
        Assert.Equal(family.Select(row => row.Generation), family.Select(row => row.Generation).Distinct());
    }

    // ============================================================ 6. 权限失效

    [Fact]
    public async Task 权限失效_账号安全版本递增使既有会话失效()
    {
        (Guid accountId, string login, string password) = await fixture.SeedAccountAsync(NextLoginName("bumpver"));
        (AuthenticationService service, _, MutableClock clock) = NewService();

        SessionIssued issued = (await service.LoginAsync(PlatformLogin(login, password))).Value;
        Assert.True((await service.ValidateSessionAsync(issued.SessionId)).IsSuccess);

        // 模拟改密/停用/风险处置：只递增安全版本，不触碰会话行
        UserAccount account = await fixture.GetAccountAsync(accountId);
        await BumpSessionVersionAsync(account);

        clock.Advance(TimeSpan.FromMinutes(1));

        Result<UserSession> validated = await service.ValidateSessionAsync(issued.SessionId);
        Assert.False(validated.IsSuccess);

        Result<SessionIssued> refreshed = await service.RefreshAsync(new RefreshCommand
        {
            RefreshToken = issued.RefreshToken,
            IdempotencyKey = Guid.NewGuid().ToString("N"),
        });
        Assert.False(refreshed.IsSuccess);
        Assert.Equal(ErrorCodes.AuthSessionTerminal, refreshed.Error!.Code);
    }

    [Fact]
    public async Task 权限失效_PLATFORM会话不得携带Organization上下文()
    {
        (_, string login, string password) = await fixture.SeedAccountAsync(NextLoginName("platscope"));
        (AuthenticationService service, _, _) = NewService();

        Result<SessionIssued> result = await service.LoginAsync(new LoginCommand
        {
            LoginName = login,
            Password = password,
            Audience = Audience.Platform,
            OrganizationId = Guid.NewGuid(),
            OrganizationMemberId = Guid.NewGuid(),
            IdempotencyKey = Guid.NewGuid().ToString("N"),
        });

        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCodes.ForbiddenClientScope, result.Error!.Code);
    }

    [Fact]
    public async Task 权限失效_PROVIDER会话在无Organization校验实现时失败关闭()
    {
        (_, string login, string password) = await fixture.SeedAccountAsync(NextLoginName("provnoverify"));
        (AuthenticationService service, _, _) = NewService(verifier: null);

        Result<SessionIssued> result = await service.LoginAsync(new LoginCommand
        {
            LoginName = login,
            Password = password,
            Audience = Audience.Provider,
            OrganizationId = Guid.NewGuid(),
            OrganizationMemberId = Guid.NewGuid(),
            IdempotencyKey = Guid.NewGuid().ToString("N"),
        });

        // 未知失败关闭：DOM-ORG-001 的查询契约没有实现时，绝不放行
        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCodes.OrganizationCapability, result.Error!.Code);
    }

    [Fact]
    public async Task 权限失效_Organization校验拒绝时不建立会话()
    {
        (_, string login, string password) = await fixture.SeedAccountAsync(NextLoginName("provdeny"));
        (AuthenticationService service, _, _) = NewService(new DenyingVerifier());

        Result<SessionIssued> result = await service.LoginAsync(new LoginCommand
        {
            LoginName = login,
            Password = password,
            Audience = Audience.Enterprise,
            OrganizationId = Guid.NewGuid(),
            OrganizationMemberId = Guid.NewGuid(),
            IdempotencyKey = Guid.NewGuid().ToString("N"),
        });

        Assert.False(result.IsSuccess);
        Assert.Equal(ErrorCodes.OrganizationCapability, result.Error!.Code);
    }

    // ============================================================ 7. 终态保护

    [Fact]
    public async Task 终态保护_REVOKED会话不可被刷新复活()
    {
        (_, string login, string password) = await fixture.SeedAccountAsync(NextLoginName("terminal"));
        (AuthenticationService service, _, MutableClock clock) = NewService();

        SessionIssued issued = (await service.LoginAsync(PlatformLogin(login, password))).Value;
        SessionIssued rotated = (await service.RefreshAsync(new RefreshCommand
        {
            RefreshToken = issued.RefreshToken,
            IdempotencyKey = Guid.NewGuid().ToString("N"),
        })).Value;

        await service.LogoutAsync(new LogoutCommand
        {
            SessionId = issued.SessionId,
            IdempotencyKey = Guid.NewGuid().ToString("N"),
        });

        clock.Advance(TimeSpan.FromMinutes(1));

        Result<SessionIssued> refreshed = await service.RefreshAsync(new RefreshCommand
        {
            RefreshToken = rotated.RefreshToken,
            IdempotencyKey = Guid.NewGuid().ToString("N"),
        });

        Assert.False(refreshed.IsSuccess);

        UserSession session = await fixture.GetSessionAsync(issued.SessionId);
        Assert.Equal(SessionStatus.Revoked, session.Status);
    }

    [Fact]
    public async Task 终态保护_REUSED令牌不可再次兑换()
    {
        (_, string login, string password) = await fixture.SeedAccountAsync(NextLoginName("reused"));
        (AuthenticationService service, _, MutableClock clock) = NewService();

        SessionIssued first = (await service.LoginAsync(PlatformLogin(login, password))).Value;
        await service.RefreshAsync(new RefreshCommand
        {
            RefreshToken = first.RefreshToken,
            IdempotencyKey = Guid.NewGuid().ToString("N"),
        });

        clock.Advance(TimeSpan.FromMinutes(1));
        await service.RefreshAsync(new RefreshCommand
        {
            RefreshToken = first.RefreshToken,
            IdempotencyKey = Guid.NewGuid().ToString("N"),
        });

        SessionRefreshToken reused = await fixture.GetTokenBySecretAsync(first.RefreshToken);
        Assert.Equal(RefreshTokenStatus.Reused, reused.Status);
        RowVersion versionAfterFirstReplay = reused.RowVersion;

        clock.Advance(TimeSpan.FromMinutes(1));
        Result<SessionIssued> third = await service.RefreshAsync(new RefreshCommand
        {
            RefreshToken = first.RefreshToken,
            IdempotencyKey = Guid.NewGuid().ToString("N"),
        });

        Assert.False(third.IsSuccess);
        // REUSED 是终态：再次重放走不可兑换分支，不重复触发处置，也不改写既有证据
        Assert.Equal(ErrorCodes.AuthTokenInvalid, third.Error!.Code);
        SessionRefreshToken unchanged = await fixture.GetTokenBySecretAsync(first.RefreshToken);
        Assert.Equal(versionAfterFirstReplay, unchanged.RowVersion);
    }

    // ============================================================ 辅助

    private async Task BumpSessionVersionAsync(UserAccount account)
    {
        (Npgsql.NpgsqlConnection connection, Npgsql.NpgsqlTransaction transaction) = await fixture.OpenAsync();
        await using (connection)
        await using (transaction)
        {
            var store = new Modules.Identity.Infrastructure.IdentityStore(connection, transaction);
            UserAccount locked = (await store.LockAccountAsync(account.Id))!;
            await store.UpdateAccountAsync(
                locked.BumpSessionVersion(), locked.RowVersion, DateTimeOffset.UtcNow, account.Id);
            await transaction.CommitAsync();
        }
    }

    private sealed class DenyingVerifier : IOrganizationContextVerifier
    {
        public Task<OrganizationContextVerdict> VerifyAsync(
            Guid userAccountId, Guid organizationId, Guid organizationMemberId,
            string requiredCapabilityCode, CancellationToken cancellationToken = default)
            => Task.FromResult(OrganizationContextVerdict.Deny("CAPABILITY_NOT_ACTIVE"));
    }
}
