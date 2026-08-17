using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Npgsql;

namespace Summer.BuildingBlocks.Infrastructure;

/// <summary>
/// 迁移执行器。
///
/// 迁移写成原生 SQL 而非由 ORM 生成，因为 §5.4.2、§5.3.5 等处要求的
/// 排他约束（<c>EXCLUDE USING gist</c>）、部分唯一索引和延迟约束
/// 是 DDL 层的业务不变量，必须逐字可评审——这正是 §5.20 第 1 项的交付物。
///
/// 每个脚本在独立事务内执行并登记摘要；摘要变化即拒绝，
/// 防止「改了已应用的迁移」这种会让各环境悄悄分叉的操作。
/// </summary>
public sealed class MigrationRunner(DatabaseOptions options, string migrationDirectory)
{
    private const string LedgerSchema = "platform";
    private const string LedgerTable = "schema_migration";

    public async Task<IReadOnlyList<string>> ApplyAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = new NpgsqlConnection(options.ConnectionString);
        await connection.OpenAsync(cancellationToken);
        await EnsureLedgerAsync(connection, cancellationToken);

        Dictionary<string, string> applied = await LoadAppliedAsync(connection, cancellationToken);
        List<string> newlyApplied = [];

        foreach (string path in EnumerateScripts())
        {
            string name = Path.GetFileName(path);
            string sql = await File.ReadAllTextAsync(path, cancellationToken);
            string checksum = Checksum(sql);

            if (applied.TryGetValue(name, out string? recorded))
            {
                if (!string.Equals(recorded, checksum, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(
                        $"迁移 {name} 已应用但内容已变（登记 {recorded}，当前 {checksum}）。" +
                        "已应用的迁移不得改写，请追加新迁移。");
                }

                continue;
            }

            await ApplyOneAsync(connection, name, sql, checksum, cancellationToken);
            newlyApplied.Add(name);
        }

        return newlyApplied;
    }

    /// <summary>按文件名升序枚举迁移脚本。序号即执行顺序，因此文件名必须零填充。</summary>
    public IEnumerable<string> EnumerateScripts()
        => Directory.EnumerateFiles(migrationDirectory, "*.sql")
            .OrderBy(Path.GetFileName, StringComparer.Ordinal);

    private static async Task EnsureLedgerAsync(NpgsqlConnection connection, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = $"""
            create schema if not exists {LedgerSchema};
            create table if not exists {LedgerSchema}.{LedgerTable} (
                script_name  varchar(200) primary key,
                checksum     char(64)     not null,
                applied_at   timestamptz  not null default now()
            );
            """;
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task<Dictionary<string, string>> LoadAppliedAsync(
        NpgsqlConnection connection, CancellationToken cancellationToken)
    {
        Dictionary<string, string> applied = new(StringComparer.Ordinal);

        await using var command = connection.CreateCommand();
        command.CommandText = $"select script_name, checksum from {LedgerSchema}.{LedgerTable}";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            applied[reader.GetString(0)] = reader.GetString(1);
        }

        return applied;
    }

    private static async Task ApplyOneAsync(
        NpgsqlConnection connection, string name, string sql, string checksum, CancellationToken cancellationToken)
    {
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);

        await using (var script = connection.CreateCommand())
        {
            script.Transaction = transaction;
            script.CommandText = sql;
            await script.ExecuteNonQueryAsync(cancellationToken);
        }

        await using (var ledger = connection.CreateCommand())
        {
            ledger.Transaction = transaction;
            ledger.CommandText =
                $"insert into {LedgerSchema}.{LedgerTable} (script_name, checksum) values (@name, @checksum)";
            ledger.Parameters.AddWithValue("name", name);
            ledger.Parameters.AddWithValue("checksum", checksum);
            await ledger.ExecuteNonQueryAsync(cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
    }

    private static string Checksum(string sql)
    {
        // 统一换行后再摘要：CRLF/LF 差异不构成内容变化，否则跨平台检出会误报。
        string normalized = sql.ReplaceLineEndings("\n");
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(normalized)));
    }

    /// <summary>供宿主与测试定位仓库内的 db/migrations 目录。</summary>
    public static string LocateMigrationDirectory()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            string candidate = Path.Combine(directory.FullName, "db", "migrations");
            if (Directory.Exists(candidate))
            {
                return candidate;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException(string.Create(CultureInfo.InvariantCulture,
            $"从 {AppContext.BaseDirectory} 向上未找到 db/migrations 目录"));
    }
}
