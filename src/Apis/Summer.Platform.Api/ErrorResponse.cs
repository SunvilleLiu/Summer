using Microsoft.AspNetCore.Mvc;
using Summer.BuildingBlocks.Application;

namespace Summer.Platform.Api;

/// <summary>
/// 把 <see cref="DomainError"/> 映射为 §8.9 的 <c>application/problem+json</c>。
///
/// <see cref="DomainError.AuditDetail"/> 一律不进响应：
/// §8.9 明确生产错误不得返回堆栈、SQL、密钥或其他主体是否存在。
/// 诊断信息只能通过审计与受限技术日志取得。
/// </summary>
public static class ErrorResponse
{
    public static IResult From(DomainError error, string? correlationId)
    {
        ArgumentNullException.ThrowIfNull(error);

        int status = StatusFor(error.Code);

        var problem = new ProblemDetails
        {
            Type = $"https://errors.summer.local/{error.Code}",
            Title = error.Message,
            Status = status,
            Detail = error.Message,
        };

        problem.Extensions["code"] = error.Code;
        problem.Extensions["correlationId"] = correlationId;
        problem.Extensions["fieldErrors"] = Array.Empty<string>();
        problem.Extensions["retryable"] = IsRetryable(error.Code);

        return Results.Problem(problem);
    }

    /// <summary>错误码前缀到 HTTP 状态的映射，取自 §8.10 目录。</summary>
    private static int StatusFor(string code)
    {
        string prefix = code.Split('-', 2)[0];

        return prefix switch
        {
            // AUTH 覆盖 401/403：凭据与令牌问题归 401，会话状态问题也归 401，
            // 因为对未认证方而言两者都应表现为「请重新登录」。
            "AUTH" => StatusCodes.Status401Unauthorized,
            "AUD" or "PERM" or "FIELD" => StatusCodes.Status403Forbidden,
            "ORG" or "WSP" or "ENTP" => StatusCodes.Status403Forbidden,
            "VALID" => StatusCodes.Status422UnprocessableEntity,
            "DUP" => StatusCodes.Status409Conflict,
            "CONC" => StatusCodes.Status409Conflict,
            "SOD" or "APPROVAL" or "BIZ" => StatusCodes.Status409Conflict,
            _ => StatusCodes.Status400BadRequest,
        };
    }

    /// <summary>并发冲突可重试；凭据与授权失败重试无意义。</summary>
    private static bool IsRetryable(string code)
        => code.StartsWith("CONC-", StringComparison.Ordinal);
}
