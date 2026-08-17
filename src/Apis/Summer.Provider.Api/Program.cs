// PROVIDER（服务机构工作端） 入口，基础路径 /provider-api/v1（docs/04-系统设计.md §8.1.1）。
//
// 本宿主目前只有存活探针，没有任何业务端点：
// 业务端点依赖 DOM-ORG-001 与 DOM-WSP-001，两模块尚未交付。
//
// 保留这个空宿主而不是删掉项目，是为了让 §4.4.1 的部署单元边界从一开始就固定，
// 避免后续把该受众的端点顺手挂到别的宿主上。

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);
WebApplication app = builder.Build();

app.MapGet("/health/live", () => Results.Ok(new { status = "LIVE" }));

app.Run();
