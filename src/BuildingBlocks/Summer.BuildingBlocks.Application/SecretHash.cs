using System.Security.Cryptography;
using System.Text;

namespace Summer.BuildingBlocks.Application;

/// <summary>
/// 令牌与验证码的摘要。
///
/// §7.2.4：访问令牌和 refresh token 只保存摘要或密钥服务引用，不明文落库。
/// §5.2.3：原始验证码、秘密和重置令牌不得落库。
///
/// 令牌本身是 256 位密码学随机值，不含可猜结构，因此摘要用 SHA-256 即可——
/// 这与用户口令不同，口令必须用自适应哈希（见 <see cref="PasswordHasher"/>）。
/// </summary>
public static class SecretHash
{
    /// <summary>生成 256 位随机秘密，以 base64url 表示，供一次性下发给客户端。</summary>
    public static string NewSecret()
    {
        Span<byte> buffer = stackalloc byte[32];
        RandomNumberGenerator.Fill(buffer);
        return Base64Url(buffer);
    }

    /// <summary>秘密的十六进制 SHA-256 摘要，长度 64，对应字段字典的 <c>char(64)</c>。</summary>
    public static string Of(string secret)
    {
        ArgumentException.ThrowIfNullOrEmpty(secret);
        Span<byte> digest = stackalloc byte[32];
        SHA256.HashData(Encoding.UTF8.GetBytes(secret), digest);
        return Convert.ToHexStringLower(digest);
    }

    private static string Base64Url(ReadOnlySpan<byte> bytes)
        => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
