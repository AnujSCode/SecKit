using SecKit.Agent;

var builder = Host.CreateApplicationBuilder(args);

// Bind configuration
builder.Services.Configure<AgentConfig>(builder.Configuration.GetSection("Agent"));

// Register SecKit services
builder.Services.AddSingleton<SecKit.Core.ConfigManager>(sp =>
    new SecKit.Core.ConfigManager(
        builder.Configuration.GetValue<string>("Agent:ConfigPath") ?? "appsettings.json"));

// Register the worker
builder.Services.AddHostedService<Worker>();

var host = builder.Build();

Spectre.Console.AnsiConsole.MarkupLine("[red]SecKit Agent v2.0[/]");
Spectre.Console.AnsiConsole.MarkupLine("[grey]Background Security Agent — Starting continuous monitoring...[/]");

await host.RunAsync();
