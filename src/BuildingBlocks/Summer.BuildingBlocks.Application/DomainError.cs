namespace Summer.BuildingBlocks.Application;

/// <summary>
/// 领域失败。§8.9：生产错误不得返回堆栈、SQL、密钥或其他 Organization/Workspace 是否存在。
/// 因此对外只暴露 <see cref="Code"/> 与 <see cref="Message"/>，
/// 诊断细节走 <see cref="AuditDetail"/>，只进审计与受限技术日志。
/// </summary>
public sealed record DomainError(string Code, string Message, string? AuditDetail = null)
{
    public static DomainError Of(string code, string message, string? auditDetail = null)
        => new(code, message, auditDetail);
}

/// <summary>命令结果：成功携带值，失败携带 <see cref="DomainError"/>。</summary>
public readonly struct Result<T>
{
    private readonly T? _value;

    internal Result(T value)
    {
        _value = value;
        Error = null;
    }

    internal Result(DomainError error)
    {
        _value = default;
        Error = error;
    }

    public DomainError? Error { get; }

    public bool IsSuccess => Error is null;

    public T Value => IsSuccess
        ? _value!
        : throw new InvalidOperationException($"结果为失败（{Error!.Code}），不得读取 Value");

    /// <summary>失败可直接由 <see cref="DomainError"/> 隐式转换，调用点写 <c>return error;</c> 即可。</summary>
    public static implicit operator Result<T>(DomainError error) => new(error);
}

/// <summary>
/// <see cref="Result{T}"/> 的工厂。放在非泛型类型上，调用点可享受类型推断。
/// </summary>
public static class Result
{
    public static Result<T> Success<T>(T value) => new(value);

    public static Result<T> Failure<T>(DomainError error) => new(error);
}
