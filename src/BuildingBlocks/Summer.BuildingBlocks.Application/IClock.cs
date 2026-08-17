namespace Summer.BuildingBlocks.Application;

/// <summary>
/// §3.1 第 6 条：数据库时间统一为 UTC。
/// 抽象出时钟是为了让「过期」「锁定期结束」这类时间守卫可被测试，而不是靠 sleep。
/// </summary>
public interface IClock
{
    DateTimeOffset UtcNow { get; }
}

public sealed class SystemClock : IClock
{
    public static SystemClock Instance { get; } = new();

    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}
