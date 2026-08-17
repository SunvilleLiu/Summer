using System.Globalization;
using System.Security.Cryptography;

namespace Summer.BuildingBlocks.Application;

/// <summary>
/// §5.2.2 要求 <c>password_hash</c> 使用「强自适应哈希」。
///
/// 采用 PBKDF2-HMAC-SHA512，参数随哈希串一并存储，因此提高迭代次数
/// 不会作废存量口令：验证按串内参数进行，<see cref="NeedsUpgrade"/> 负责标记待升级。
/// </summary>
public static class PasswordHasher
{
    private const string Algorithm = "pbkdf2-sha512";
    private const int SaltBytes = 16;
    private const int KeyBytes = 64;

    /// <summary>当前迭代次数。提高此值只影响新哈希，验证仍按各自串内参数进行。</summary>
    public const int CurrentIterations = 210_000;

    public static string Hash(string password)
    {
        ArgumentException.ThrowIfNullOrEmpty(password);

        byte[] salt = RandomNumberGenerator.GetBytes(SaltBytes);
        byte[] key = Rfc2898DeriveBytes.Pbkdf2(password, salt, CurrentIterations, HashAlgorithmName.SHA512, KeyBytes);

        return string.Create(CultureInfo.InvariantCulture,
            $"{Algorithm}${CurrentIterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(key)}");
    }

    /// <summary>
    /// 校验口令。任何格式异常一律按「不匹配」处理，不抛异常——
    /// 抛异常会让攻击者从响应差异里区分「哈希损坏」与「口令错误」。
    /// </summary>
    public static bool Verify(string password, string encoded)
    {
        if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(encoded))
        {
            return false;
        }

        if (!TryParse(encoded, out int iterations, out byte[]? salt, out byte[]? expected))
        {
            return false;
        }

        byte[] actual = Rfc2898DeriveBytes.Pbkdf2(
            password, salt, iterations, HashAlgorithmName.SHA512, expected.Length);

        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    /// <summary>存量哈希的迭代次数低于当前基线时为 true，调用方可在下次登录成功后重算。</summary>
    public static bool NeedsUpgrade(string encoded)
        => !TryParse(encoded, out int iterations, out _, out _) || iterations < CurrentIterations;

    private static bool TryParse(string encoded, out int iterations, out byte[] salt, out byte[] key)
    {
        iterations = 0;
        salt = [];
        key = [];

        string[] parts = encoded.Split('$');
        if (parts.Length != 4 || !string.Equals(parts[0], Algorithm, StringComparison.Ordinal))
        {
            return false;
        }

        if (!int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out iterations) || iterations <= 0)
        {
            return false;
        }

        try
        {
            salt = Convert.FromBase64String(parts[2]);
            key = Convert.FromBase64String(parts[3]);
        }
        catch (FormatException)
        {
            return false;
        }

        return salt.Length > 0 && key.Length > 0;
    }
}
