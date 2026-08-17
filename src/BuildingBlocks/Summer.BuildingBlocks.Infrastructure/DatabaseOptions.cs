namespace Summer.BuildingBlocks.Infrastructure;

/// <summary>
/// PostgreSQL 连接配置。技术基线见 docs/04-系统设计.md §4。
/// 连接串不落代码库：由环境变量 <see cref="EnvironmentVariable"/> 提供。
/// </summary>
public sealed record DatabaseOptions(string ConnectionString)
{
    public const string EnvironmentVariable = "SUMMER_DB";

    /// <summary>
    /// 从环境读取连接串。缺失即抛出——静默回退到本地默认值会让生产误连开发库。
    /// </summary>
    public static DatabaseOptions FromEnvironment()
    {
        string? value = Environment.GetEnvironmentVariable(EnvironmentVariable);
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidOperationException(
                $"未设置环境变量 {EnvironmentVariable}，无法建立 PostgreSQL 连接");
        }

        return new DatabaseOptions(value);
    }
}
