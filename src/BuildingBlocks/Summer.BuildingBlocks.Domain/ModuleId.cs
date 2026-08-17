namespace Summer.BuildingBlocks.Domain;

/// <summary>
/// 稳定领域 ID，取自 docs/04-系统设计.md §4.4.1。
/// 这些 ID 是跨文档追踪键：英文显示名可调整，ID 不得复用或改写。
/// 把它们放进代码而不是注释里，是为了让「模块只写本模块拥有的表」这条边界可被机检。
/// </summary>
public static class ModuleId
{
    public const string Identity = "DOM-IAM-001";
    public const string Organization = "DOM-ORG-001";
    public const string Authorization = "DOM-IAM-002";
    public const string Workspace = "DOM-WSP-001";
    public const string Customer = "DOM-CRM-001";
    public const string Contract = "DOM-CTR-001";
    public const string OperatingFinance = "DOM-FIN-001";
    public const string Service = "DOM-SVC-001";
    public const string Accounting = "DOM-ACC-001";
    public const string Tax = "DOM-TAX-001";
    public const string CommercialBilling = "DOM-BILL-001";
    public const string InternalManagement = "DOM-INT-001";
    public const string EnterpriseCollaboration = "DOM-ENTP-001";
    public const string Integration = "DOM-CONN-001";
    public const string Reporting = "DOM-RPT-001";
    public const string PublicCapabilities = "DOM-PUB-001";
}

/// <summary>
/// 每个模块声明自己拥有哪些 PostgreSQL schema 与表。
/// docs/04-系统设计.md §4.3.1：模块只写本模块拥有的表；跨模块读取走公开查询契约。
/// 声明是给机检用的事实来源，不是给人看的文档。
/// </summary>
public interface IModuleDescriptor
{
    /// <summary>稳定领域 ID，见 <see cref="ModuleId"/>。</summary>
    static abstract string DomainId { get; }

    /// <summary>本模块拥有的逻辑 schema，取值见 docs/04-系统设计.md §4.7.1。</summary>
    static abstract IReadOnlyList<string> OwnedSchemas { get; }
}
