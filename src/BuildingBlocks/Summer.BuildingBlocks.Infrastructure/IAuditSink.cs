using Npgsql;
using Summer.BuildingBlocks.Application;

namespace Summer.BuildingBlocks.Infrastructure;

/// <summary>
/// 审计事实的落点。
///
/// §4.6 要求同一事务写业务聚合、关键流水、审计摘要与 Outbox，
/// 因此签名里带调用方的连接与事务——审计不能自开事务：
/// 业务回滚而审计已提交，会留下「发生过但其实没发生」的事实。
///
/// 审计表 <c>audit_event</c> 属 ENT-PUB-001 / DOM-PUB-001（§5.2.1），
/// 而 §4.3.1 规定模块只写本模块拥有的表，因此各业务模块只能通过本抽象发出事实，
/// 由 PublicCapabilities 负责落库与维护哈希链。
///
/// 本接口刻意不带空实现：一个「什么都不做」的默认实现会让审计链在无人察觉时断掉，
/// 而 §6 把审计链断裂列为必须告警的安全事件。
/// </summary>
public interface IAuditSink
{
    /// <summary>在调用方的事务内追加一条审计事实。</summary>
    Task WriteAsync(
        AuditEntry entry,
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        CancellationToken cancellationToken = default);
}
