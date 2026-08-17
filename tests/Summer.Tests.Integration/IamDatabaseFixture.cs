using Npgsql;
using Summer.BuildingBlocks.Application;
using Summer.BuildingBlocks.Infrastructure;
using Summer.Modules.Identity.Domain;
using Summer.Modules.Identity.Infrastructure;
using Xunit;

namespace Summer.Tests.Integration;

/// <summary>
/// 集成测试的 PostgreSQL 夹具。
///
/// 跑真实数据库而不是内存替身，因为本纵切一半的不变量写在 DDL 里：
/// 受众作用域检查、<c>unique(family_id, generation)</c>、CONSUMED 的后继非空约束。
/// 用替身测这些等于不测。
/// </summary>
public sealed class IamDatabaseFixture : IAsyncLifetime
{
    public const string ConnectionStringVariable = "SUMMER_DB_TEST";

    public DatabaseOptions Options { get; private set; } = null!;

    /// <summary>
    /// 测试用的策略数值。**这些不是 DEC-IAM-001 的冻结值**，只是让测试可跑的试验值：
    /// 会话 5 分钟、refresh 30 分钟、3 次失败锁定 15 分钟。
    /// 生产值必须由 OWNER 在 GATE-LLD 冻结后经环境变量提供。
    /// </summary>
    public static SessionPolicy TestPolicy { get; } = SessionPolicy.Create(
        accessTokenLifetime: TimeSpan.FromMinutes(5),
        refreshTokenLifetime: TimeSpan.FromMinutes(30),
        maxFailedAttempts: 3,
        lockoutDuration: TimeSpan.FromMinutes(15));

    public async Task InitializeAsync()
    {
        string? connectionString = Environment.GetEnvironmentVariable(ConnectionStringVariable);
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            throw new InvalidOperationException(
                $"集成测试需要环境变量 {ConnectionStringVariable} 指向可写的测试库。" +
                "跳过而不是失败会让 CI 在没有数据库时报绿，这比测试失败更危险。");
        }

        Options = new DatabaseOptions(connectionString);

        // 每轮从零重建：迁移执行器按摘要拒绝已应用脚本的改写，
        // 保留旧 schema 会让「改了迁移」的测试运行直接失败而不是重跑。
        //
        // 按枚举结果清空而不是写死 schema 名单：名单漏掉一个新 schema 时，
        // 迁移登记表已被清掉而那个 schema 的表还在，下一轮会以
        // 「relation already exists」失败——症状离原因很远，排查代价高。
        await using (var connection = new NpgsqlConnection(connectionString))
        {
            await connection.OpenAsync();
            await using var drop = connection.CreateCommand();
            drop.CommandText = """
                do $$
                declare target text;
                begin
                    for target in
                        select nspname from pg_namespace
                        where nspname not in ('pg_catalog', 'information_schema', 'public')
                          and nspname not like 'pg\_%'
                    loop
                        execute format('drop schema %I cascade', target);
                    end loop;
                end $$;
                """;
            await drop.ExecuteNonQueryAsync();
        }

        var runner = new MigrationRunner(Options, MigrationRunner.LocateMigrationDirectory());
        await runner.ApplyAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    /// <summary>打开一个连接与事务，供测试直接检查库内事实。</summary>
    public async Task<(NpgsqlConnection Connection, NpgsqlTransaction Transaction)> OpenAsync()
    {
        var connection = new NpgsqlConnection(Options.ConnectionString);
        await connection.OpenAsync();
        NpgsqlTransaction transaction = await connection.BeginTransactionAsync();
        return (connection, transaction);
    }

    /// <summary>植入一个 ACTIVE 账号，返回其明文口令供登录测试使用。</summary>
    public async Task<(Guid AccountId, string LoginName, string Password)> SeedAccountAsync(
        string loginName, string password = "Correct-Horse-Battery-1", AccountStatus status = AccountStatus.Active)
    {
        Guid id = Guid.NewGuid();
        var account = new UserAccount
        {
            Id = id,
            LoginNameNormalized = loginName,
            PasswordHash = PasswordHasher.Hash(password),
            SessionVersion = 1,
            FailedCount = 0,
            Status = status,
            RowVersion = BuildingBlocks.Domain.RowVersion.Initial,
        };

        (NpgsqlConnection connection, NpgsqlTransaction transaction) = await OpenAsync();
        await using (connection)
        await using (transaction)
        {
            var store = new IdentityStore(connection, transaction);
            await store.InsertAccountAsync(account, DateTimeOffset.UtcNow);
            await transaction.CommitAsync();
        }

        return (id, loginName, password);
    }

    /// <summary>读取账号当前状态，用于断言登录保护与安全版本的实际落库结果。</summary>
    public async Task<UserAccount> GetAccountAsync(Guid id)
    {
        (NpgsqlConnection connection, NpgsqlTransaction transaction) = await OpenAsync();
        await using (connection)
        await using (transaction)
        {
            var store = new IdentityStore(connection, transaction);
            UserAccount account = await store.LockAccountAsync(id)
                ?? throw new InvalidOperationException($"账号 {id} 不存在");
            await transaction.CommitAsync();
            return account;
        }
    }

    public async Task<UserSession> GetSessionAsync(Guid id)
    {
        (NpgsqlConnection connection, NpgsqlTransaction transaction) = await OpenAsync();
        await using (connection)
        await using (transaction)
        {
            var store = new IdentityStore(connection, transaction);
            UserSession session = await store.LockSessionAsync(id)
                ?? throw new InvalidOperationException($"会话 {id} 不存在");
            await transaction.CommitAsync();
            return session;
        }
    }

    /// <summary>按摘要读取令牌行，用于断言旋转链与重放处置的落库结果。</summary>
    public async Task<SessionRefreshToken> GetTokenBySecretAsync(string secret)
    {
        (NpgsqlConnection connection, NpgsqlTransaction transaction) = await OpenAsync();
        await using (connection)
        await using (transaction)
        {
            var store = new IdentityStore(connection, transaction);
            SessionRefreshToken token = await store.LockRefreshTokenByHashAsync(SecretHash.Of(secret))
                ?? throw new InvalidOperationException("令牌不存在");
            await transaction.CommitAsync();
            return token;
        }
    }

    public async Task<IReadOnlyList<(int Generation, RefreshTokenStatus Status)>> GetFamilyAsync(Guid familyId)
    {
        List<(int, RefreshTokenStatus)> rows = [];

        await using var connection = new NpgsqlConnection(Options.ConnectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText =
            "select generation, status from iam.session_refresh_token where family_id = @f order by generation";
        command.Parameters.AddWithValue("f", familyId);

        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            rows.Add((reader.GetInt32(0), IdentityCodes.ParseRefreshTokenStatus(reader.GetString(1))));
        }

        return rows;
    }
}

[CollectionDefinition(nameof(IamDatabaseCollection))]
public sealed class IamDatabaseCollection : ICollectionFixture<IamDatabaseFixture>;
