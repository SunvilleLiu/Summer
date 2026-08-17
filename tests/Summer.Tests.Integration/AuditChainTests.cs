using Npgsql;
using Summer.BuildingBlocks.Application;
using Summer.BuildingBlocks.Domain;
using Summer.BuildingBlocks.Infrastructure;
using Summer.Modules.Identity.Application;
using Summer.Modules.Identity.Contracts;
using Summer.Modules.PublicCapabilities.Infrastructure;
using Xunit;

namespace Summer.Tests.Integration;

/// <summary>
/// <c>audit.audit_event</c> 哈希链的行为（docs/04-系统设计.md §5.6.3、§5.19）。
///
/// 未覆盖：<c>audit_partition_anchor</c> 的分区封存与签名校验——
/// 该部分依赖尚未冻结的密钥服务（§4.11 第 6 项），本次未实现，故无代码可测。
/// </summary>
[Collection(nameof(IamDatabaseCollection))]
public sealed class AuditChainTests(IamDatabaseFixture fixture)
{
    private static readonly DateTimeOffset Origin = new(2026, 3, 2, 10, 0, 0, TimeSpan.Zero);

    private static AuditEntry Entry(string eventType, Guid? organizationId = null, AuditRisk risk = AuditRisk.Normal)
        => new()
        {
            EventType = eventType,
            OccurredAt = Origin,
            AudienceCode = organizationId is null ? "PLATFORM" : "PROVIDER",
            OrganizationId = organizationId,
            ObjectType = "user_session",
            ObjectId = Guid.NewGuid(),
            ReasonCode = "TEST",
            Risk = risk,
        };

    private async Task<T> InTransactionAsync<T>(Func<NpgsqlConnection, NpgsqlTransaction, Task<T>> work, bool commit)
    {
        await using var connection = new NpgsqlConnection(fixture.Options.ConnectionString);
        await connection.OpenAsync();
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync();

        T result = await work(connection, transaction);

        if (commit)
        {
            await transaction.CommitAsync();
        }
        else
        {
            await transaction.RollbackAsync();
        }

        return result;
    }

    private async Task<IReadOnlyList<(long Sequence, string Hash, string? PreviousHash, string EventType)>>
        ReadChainAsync(string chainScopeType, Guid chainScopeId)
    {
        List<(long, string, string?, string)> rows = [];

        await using var connection = new NpgsqlConnection(fixture.Options.ConnectionString);
        await connection.OpenAsync();
        await using NpgsqlCommand command = connection.CreateCommand();
        command.CommandText = """
            select chain_sequence, event_hash, previous_event_hash, event_type
            from audit.audit_event
            where chain_scope_type = @t and chain_scope_id = @i
            order by chain_sequence
            """;
        command.Parameters.AddWithValue("t", chainScopeType);
        command.Parameters.AddWithValue("i", chainScopeId);

        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            rows.Add((reader.GetInt64(0), reader.GetString(1),
                reader.IsDBNull(2) ? null : reader.GetString(2), reader.GetString(3)));
        }

        return rows;
    }

    [Fact]
    public async Task 审计链_同一链内序号连续且前序哈希首尾相接()
    {
        var sink = new PostgresAuditSink();
        Guid organizationId = Guid.NewGuid();

        await InTransactionAsync(async (connection, transaction) =>
        {
            for (int i = 0; i < 3; i++)
            {
                await sink.WriteAsync(Entry($"test.chain.{i}", organizationId), connection, transaction);
            }

            return true;
        }, commit: true);

        IReadOnlyList<(long Sequence, string Hash, string? PreviousHash, string EventType)> chain =
            await ReadChainAsync("ORGANIZATION", organizationId);

        Assert.Equal(3, chain.Count);
        Assert.Equal([1L, 2L, 3L], chain.Select(r => r.Sequence));

        // 链首无前序，其后每条的前序必须等于上一条的哈希
        Assert.Null(chain[0].PreviousHash);
        Assert.Equal(chain[0].Hash, chain[1].PreviousHash);
        Assert.Equal(chain[1].Hash, chain[2].PreviousHash);

        // 哈希各不相同：相同说明输入没有把序号或前序纳入计算
        Assert.Equal(3, chain.Select(r => r.Hash).Distinct().Count());
    }

    [Fact]
    public async Task 审计链_PLATFORM事件与Organization事件不共用同一条链()
    {
        var sink = new PostgresAuditSink();
        Guid organizationId = Guid.NewGuid();

        await InTransactionAsync(async (connection, transaction) =>
        {
            await sink.WriteAsync(Entry("test.platform.only"), connection, transaction);
            await sink.WriteAsync(Entry("test.org.only", organizationId), connection, transaction);
            return true;
        }, commit: true);

        IReadOnlyList<(long Sequence, string Hash, string? PreviousHash, string EventType)> orgChain =
            await ReadChainAsync("ORGANIZATION", organizationId);

        // §1.8.3：PLATFORM 事件不得伪造 organizationId，因此它进的是平台链
        Assert.Single(orgChain);
        Assert.Equal("test.org.only", orgChain[0].EventType);
        Assert.Equal(1L, orgChain[0].Sequence);
    }

    [Fact]
    public async Task 审计链_业务事务回滚时审计不留痕()
    {
        var sink = new PostgresAuditSink();
        Guid organizationId = Guid.NewGuid();

        await InTransactionAsync(async (connection, transaction) =>
        {
            await sink.WriteAsync(Entry("test.rollback", organizationId), connection, transaction);
            return true;
        }, commit: false);

        // §4.6：审计与业务同事务。若审计另开连接，这里会留下一条「发生过但其实没发生」的记录。
        Assert.Empty(await ReadChainAsync("ORGANIZATION", organizationId));
    }

    [Fact]
    public async Task 审计链_数据库层拒绝删除与改写()
    {
        var sink = new PostgresAuditSink();
        Guid organizationId = Guid.NewGuid();

        await InTransactionAsync(async (connection, transaction) =>
        {
            await sink.WriteAsync(Entry("test.immutable", organizationId), connection, transaction);
            return true;
        }, commit: true);

        await using var connection = new NpgsqlConnection(fixture.Options.ConnectionString);
        await connection.OpenAsync();

        await using (NpgsqlCommand delete = connection.CreateCommand())
        {
            delete.CommandText = "delete from audit.audit_event where chain_scope_id = @i";
            delete.Parameters.AddWithValue("i", organizationId);
            await delete.ExecuteNonQueryAsync();
        }

        await using (NpgsqlCommand update = connection.CreateCommand())
        {
            update.CommandText = "update audit.audit_event set event_type = 'tampered' where chain_scope_id = @i";
            update.Parameters.AddWithValue("i", organizationId);
            await update.ExecuteNonQueryAsync();
        }

        // §5.19：审计不得物理删除。规则让 delete/update 静默失效——
        // 绕过应用层的直连同样改不动。
        IReadOnlyList<(long Sequence, string Hash, string? PreviousHash, string EventType)> chain =
            await ReadChainAsync("ORGANIZATION", organizationId);
        Assert.Single(chain);
        Assert.Equal("test.immutable", chain[0].EventType);
    }

    [Fact]
    public async Task 审计链_登录纵切经真实落点写入平台链()
    {
        (_, string login, string password) = await fixture.SeedAccountAsync(
            $"auditflow-{Guid.NewGuid():N}"[..30]);

        var clock = new MutableClock(Origin);
        var service = new AuthenticationService(
            fixture.Options, IamDatabaseFixture.TestPolicy, clock, new PostgresAuditSink());

        long before = await CountPlatformEventsAsync("iam.session.started");

        Result<SessionIssued> result = await service.LoginAsync(new LoginCommand
        {
            LoginName = login,
            Password = password,
            Audience = Audience.Platform,
            IdempotencyKey = Guid.NewGuid().ToString("N"),
        });

        Assert.True(result.IsSuccess);
        Assert.Equal(before + 1, await CountPlatformEventsAsync("iam.session.started"));

        // 重放触发的高风险审计也必须落库
        SessionIssued issued = result.Value;
        clock.Advance(TimeSpan.FromMinutes(1));
        await service.RefreshAsync(new RefreshCommand
        {
            RefreshToken = issued.RefreshToken,
            IdempotencyKey = Guid.NewGuid().ToString("N"),
        });
        clock.Advance(TimeSpan.FromMinutes(1));
        await service.RefreshAsync(new RefreshCommand
        {
            RefreshToken = issued.RefreshToken,
            IdempotencyKey = Guid.NewGuid().ToString("N"),
        });

        Assert.True(await CountHighRiskAsync("iam.session.refresh_reuse_detected") >= 1);
    }

    private async Task<long> CountPlatformEventsAsync(string eventType)
    {
        await using var connection = new NpgsqlConnection(fixture.Options.ConnectionString);
        await connection.OpenAsync();
        await using NpgsqlCommand command = connection.CreateCommand();
        command.CommandText =
            "select count(*) from audit.audit_event where event_type = @t and chain_scope_type = 'PLATFORM'";
        command.Parameters.AddWithValue("t", eventType);
        return (long)(await command.ExecuteScalarAsync())!;
    }

    private async Task<long> CountHighRiskAsync(string eventType)
    {
        await using var connection = new NpgsqlConnection(fixture.Options.ConnectionString);
        await connection.OpenAsync();
        await using NpgsqlCommand command = connection.CreateCommand();
        command.CommandText =
            "select count(*) from audit.audit_event where event_type = @t and risk_level = 'HIGH'";
        command.Parameters.AddWithValue("t", eventType);
        return (long)(await command.ExecuteScalarAsync())!;
    }
}
