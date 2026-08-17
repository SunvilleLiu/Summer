using Summer.BuildingBlocks.Domain;

namespace Summer.Modules.PublicCapabilities;

/// <summary>
/// DOM-PUB-001 PublicCapabilities：审批、待办、附件、通知、审计、导入导出、后台任务和 Outbox
/// （docs/04-系统设计.md §4.4.2）。
///
/// 已交付：<c>audit_event</c> 哈希链。
/// 未交付：审批、待办、附件、通知、导入导出、job_task、Outbox。
/// </summary>
public sealed class PublicCapabilitiesModule : IModuleDescriptor
{
    public static string DomainId => ModuleId.PublicCapabilities;

    public static IReadOnlyList<string> OwnedSchemas => ["audit"];
}
