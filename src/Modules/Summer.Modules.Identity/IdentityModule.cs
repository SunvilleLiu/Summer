using Summer.BuildingBlocks.Domain;

namespace Summer.Modules.Identity;

/// <summary>
/// DOM-IAM-001 Identity：登录、MFA、challenge、会话（docs/04-系统设计.md §4.4.2）。
/// 本模块只写 iam schema；Organization 成员关系属 DOM-ORG-001，跨模块只读查询契约。
/// </summary>
public sealed class IdentityModule : IModuleDescriptor
{
    public static string DomainId => ModuleId.Identity;

    public static IReadOnlyList<string> OwnedSchemas => ["iam"];
}
