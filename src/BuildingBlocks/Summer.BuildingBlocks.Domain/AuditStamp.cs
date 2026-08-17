namespace Summer.BuildingBlocks.Domain;

/// <summary>
/// docs/04-系统设计.md §5.1.2 通用列中的创建/更新证据。
/// 创建证据不可覆盖（标记 S/I），当前投影的更新证据每次有效更新重写。
/// </summary>
public readonly record struct AuditStamp(
    DateTimeOffset CreatedAt,
    Guid CreatedBy,
    DateTimeOffset UpdatedAt,
    Guid UpdatedBy)
{
    public static AuditStamp Create(DateTimeOffset at, Guid by) => new(at, by, at, by);

    public AuditStamp Touch(DateTimeOffset at, Guid by) => this with { UpdatedAt = at, UpdatedBy = by };
}

/// <summary>
/// 乐观锁 <c>row_version</c>（§5.1.2）：每次有效更新递增。
/// 与状态决定用的 <c>status_version</c> 是两回事，后者由各聚合自己持有。
/// </summary>
public readonly record struct RowVersion(long Value)
{
    public static RowVersion Initial => new(1);

    public RowVersion Next() => new(Value + 1);

    public override string ToString() => Value.ToString(System.Globalization.CultureInfo.InvariantCulture);
}
