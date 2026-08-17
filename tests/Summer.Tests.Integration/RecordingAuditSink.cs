using Npgsql;
using Summer.BuildingBlocks.Application;
using Summer.BuildingBlocks.Infrastructure;

namespace Summer.Tests.Integration;

/// <summary>
/// 把审计事实记在内存里供断言。
///
/// 这不是「审计已实现」：<c>audit_event</c> 属 ENT-PUB-001 / DOM-PUB-001，
/// 落库随 PublicCapabilities 模块交付。本类只保证 Identity **产生了**正确的审计事实，
/// 使 §3.1 第 3 条在本纵切范围内可验证。
/// </summary>
public sealed class RecordingAuditSink : IAuditSink
{
    private readonly List<AuditEntry> _entries = [];

    public IReadOnlyList<AuditEntry> Entries => _entries;

    public Task WriteAsync(
        AuditEntry entry,
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        CancellationToken cancellationToken = default)
    {
        _entries.Add(entry);
        return Task.CompletedTask;
    }

    public IEnumerable<AuditEntry> OfType(string eventType)
        => _entries.Where(e => string.Equals(e.EventType, eventType, StringComparison.Ordinal));

    public void Clear() => _entries.Clear();
}

/// <summary>可拨动的时钟，用来测过期与锁定期，避免测试里出现 sleep。</summary>
public sealed class MutableClock(DateTimeOffset now) : IClock
{
    public DateTimeOffset UtcNow { get; private set; } = now;

    public void Advance(TimeSpan by) => UtcNow += by;
}
