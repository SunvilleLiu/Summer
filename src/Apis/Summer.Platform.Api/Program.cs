using Summer.BuildingBlocks.Application;
using Summer.BuildingBlocks.Domain;
using Summer.BuildingBlocks.Infrastructure;
using Summer.Modules.Identity.Application;
using Summer.Modules.Identity.Contracts;
using Summer.Modules.Identity.Domain;
using Summer.Modules.PublicCapabilities.Infrastructure;
using Summer.Platform.Api;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

// 配置全部来自环境，缺失即启动失败。
// SessionPolicy 的数值属未冻结的 DEC-IAM-001，实现方不得代填默认值。
builder.Services.AddSingleton(DatabaseOptions.FromEnvironment());
builder.Services.AddSingleton(SessionPolicy.FromEnvironment());
builder.Services.AddSingleton<IClock>(SystemClock.Instance);

// 审计落点由 DOM-PUB-001（PublicCapabilities）提供，写入调用方的同一事务（§4.6）。
builder.Services.AddSingleton<IAuditSink, PostgresAuditSink>();

builder.Services.AddScoped<AuthenticationService>(sp => new AuthenticationService(
    sp.GetRequiredService<DatabaseOptions>(),
    sp.GetRequiredService<SessionPolicy>(),
    sp.GetRequiredService<IClock>(),
    sp.GetRequiredService<IAuditSink>(),
    sp.GetService<IOrganizationContextVerifier>()));

builder.Services.AddProblemDetails();

WebApplication app = builder.Build();

// -----------------------------------------------------------------------------
// PLATFORM 入口，基础路径见 §8.1.1。
// 登录属 §7.2.5 的受限认证能力，不走业务 RBAC。
// -----------------------------------------------------------------------------
RouteGroupBuilder sessions = app.MapGroup("/platform-api/v1/sessions");

sessions.MapPost("/", async (
    LoginRequest request,
    AuthenticationService service,
    HttpContext context,
    CancellationToken cancellationToken) =>
{
    string? correlationId = context.Request.Headers["X-Correlation-Id"].FirstOrDefault();

    if (!TryGetIdempotencyKey(context, out string idempotencyKey))
    {
        return ErrorResponse.From(
            DomainError.Of(ErrorCodes.IdempotencyMismatch, "命令必须携带 Idempotency-Key"), correlationId);
    }

    Result<SessionIssued> result = await service.LoginAsync(new LoginCommand
    {
        LoginName = request.LoginName,
        Password = request.Password,
        // 受众由入口固定，不读请求体：§8.2.1 规定 PLATFORM 令牌不得携带其他受众上下文，
        // 让客户端提交 audience 等于把受众隔离交给客户端决定。
        Audience = Audience.Platform,
        IdempotencyKey = idempotencyKey,
        CorrelationId = correlationId,
    }, cancellationToken);

    return result.IsSuccess
        ? Results.Ok(SessionResponse.From(result.Value))
        : ErrorResponse.From(result.Error!, correlationId);
});

sessions.MapPost("/:refresh", async (
    RefreshRequest request,
    AuthenticationService service,
    HttpContext context,
    CancellationToken cancellationToken) =>
{
    string? correlationId = context.Request.Headers["X-Correlation-Id"].FirstOrDefault();

    if (!TryGetIdempotencyKey(context, out string idempotencyKey))
    {
        return ErrorResponse.From(
            DomainError.Of(ErrorCodes.IdempotencyMismatch, "命令必须携带 Idempotency-Key"), correlationId);
    }

    Result<SessionIssued> result = await service.RefreshAsync(new RefreshCommand
    {
        RefreshToken = request.RefreshToken,
        IdempotencyKey = idempotencyKey,
        CorrelationId = correlationId,
    }, cancellationToken);

    return result.IsSuccess
        ? Results.Ok(SessionResponse.From(result.Value))
        : ErrorResponse.From(result.Error!, correlationId);
});

sessions.MapPost("/{sessionId:guid}:revoke", async (
    Guid sessionId,
    AuthenticationService service,
    HttpContext context,
    CancellationToken cancellationToken) =>
{
    string? correlationId = context.Request.Headers["X-Correlation-Id"].FirstOrDefault();

    if (!TryGetIdempotencyKey(context, out string idempotencyKey))
    {
        return ErrorResponse.From(
            DomainError.Of(ErrorCodes.IdempotencyMismatch, "命令必须携带 Idempotency-Key"), correlationId);
    }

    Result<bool> result = await service.LogoutAsync(new LogoutCommand
    {
        SessionId = sessionId,
        IdempotencyKey = idempotencyKey,
        CorrelationId = correlationId,
    }, cancellationToken);

    return result.IsSuccess
        ? Results.NoContent()
        : ErrorResponse.From(result.Error!, correlationId);
});

app.Run();

static bool TryGetIdempotencyKey(HttpContext context, out string key)
{
    // §3.1 第 1 条 / §8.1.2：改变状态的命令必须携带 Idempotency-Key。
    // 注意：本次只强制**存在**，尚未实现「同键异摘要返回冲突」的去重存储——
    // 去重事实属 DOM-PUB-001，随该模块交付。
    string? value = context.Request.Headers["Idempotency-Key"].FirstOrDefault();
    key = value ?? string.Empty;
    return !string.IsNullOrWhiteSpace(value);
}

internal sealed record LoginRequest(string LoginName, string Password);

internal sealed record RefreshRequest(string RefreshToken);

internal sealed record SessionResponse(
    Guid SessionId,
    string SessionNo,
    string RefreshToken,
    DateTimeOffset ExpiresAt,
    DateTimeOffset RefreshTokenExpiresAt)
{
    public static SessionResponse From(SessionIssued issued) => new(
        issued.SessionId, issued.SessionNo, issued.RefreshToken, issued.ExpiresAt, issued.RefreshTokenExpiresAt);
}

/// <summary>供集成测试通过 WebApplicationFactory 引用本宿主。</summary>
public partial class Program;
