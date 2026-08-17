// Platform.Worker：后台任务与 Outbox 派发（docs/04-系统设计.md §4.7.3、§4.8.1）。
//
// 目前没有任何队列消费者：Outbox 与 job_task 属 ENT-PUB-001 / DOM-PUB-001，
// 该模块尚未交付。Worker 使用 FOR UPDATE SKIP LOCKED 领取任务的机制随其一并实现。

using Microsoft.Extensions.Hosting;

IHost host = Host.CreateApplicationBuilder(args).Build();
await host.RunAsync();
