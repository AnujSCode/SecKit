using SecKit.Core;
using SecKit.Models;
using SecKit.Modules.VulnerabilityScanner;
using SecKit.Modules.NetworkScanner;
using SecKit.Modules.AiSecurityTester;
using SecKit.Modules.TrafficMonitor;
using SecKit.Modules.SiteMapper;
using SecKit.Modules.TrafficAnalysis;

using Spectre.Console;

namespace SecKit;

/// <summary>SecKit — .NET Security Toolkit. Interactive menu-driven CLI for web application security testing.</summary>
public class Program
{
    private static ConfigManager _config = null!;
    private static HttpClient _httpClient = null!;

    public static async Task<int> Main(string[] args)
    {
        // Parse CLI args for non-interactive mode
        if (args.Length > 0)
        {
            return await RunNonInteractiveAsync(args);
        }

        return await RunInteractiveAsync();
    }

    /// <summary>Runs the interactive menu-driven CLI.</summary>
    private static async Task<int> RunInteractiveAsync()
    {
        try
        {
            _config = new ConfigManager();
            _httpClient = HttpClientFactory.Create(_config);

            Logger.Initialize(Path.Combine(_config.OutputDirectory, "seckit.log"));

            // Splash screen
            AnsiConsole.Write(new FigletText("SecKit").Color(Color.Red));
            AnsiConsole.MarkupLine("[grey]Security Toolkit v1.0.0 — .NET 8[/]");
            AnsiConsole.MarkupLine($"[grey]Profile: {_config.ActiveProfile} | Threads: {_config.Threads} | Timeout: {_config.TimeoutSeconds}s[/]");
            AnsiConsole.WriteLine();

            // Authorization gate — active scanning without permission may be illegal.
            AnsiConsole.Write(new Panel(
                "[yellow]SecKit performs active security testing that sends real attack traffic.[/]\n" +
                "Only scan systems you [bold]own[/] or have [bold]explicit written permission[/] to test.\n" +
                "Unauthorized scanning may violate the CFAA, the UK Computer Misuse Act, and similar laws.")
                .Header("[red] LEGAL NOTICE [/]")
                .BorderColor(Color.Red));

            if (!AnsiConsole.Confirm("[red]I confirm I am authorized to test the targets I will enter. Continue?[/]", false))
            {
                AnsiConsole.MarkupLine("[grey]Aborted.[/]");
                return 0;
            }
            AnsiConsole.WriteLine();

            while (true)
            {
                var choice = AnsiConsole.Prompt(
                    new SelectionPrompt<string>()
                        .Title("[yellow]Select an option:[/]")
                        .HighlightStyle(new Style(foreground: Color.Black, background: Color.Yellow))
                        .AddChoices(new[]
                        {
                            "1. Vulnerability Scan (SQLi, XSS, CSRF, SSRF, Path Traversal, Auth, File Upload)",
                            "2. Network Scan (Ports, SSL/TLS, Headers)",
                            "3. AI Security Test (Prompt Injection, Function Abuse, Data Leakage)",
                            "4. Site Map (Crawl + Fuzz)",
                            "5. Traffic Monitor (Live Log Watch + Attack Detection)",
                            "6. Traffic Analysis (GeoIP, Honeypot, Subdomain Enum)",
                            "7. 💥 Full Suite (All of the above)",
                            "8. ⚙️  Settings",
                            "9. ❌ Exit"
                        }));

                switch (choice)
                {
                    case string s when s.StartsWith("1"):
                        await RunVulnerabilityScanAsync();
                        break;
                    case string s when s.StartsWith("2"):
                        await RunNetworkScanAsync();
                        break;
                    case string s when s.StartsWith("3"):
                        await RunAiSecurityTestAsync();
                        break;
                    case string s when s.StartsWith("4"):
                        await RunSiteMapAsync();
                        break;
                    case string s when s.StartsWith("5"):
                        await RunTrafficMonitorAsync();
                        break;
                    case string s when s.StartsWith("6"):
                        await RunTrafficAnalysisAsync();
                        break;
                    case string s when s.StartsWith("7"):
                        await RunFullSuiteAsync();
                        break;
                    case string s when s.StartsWith("8"):
                        ShowSettings();
                        break;
                    case string s when s.StartsWith("9"):
                        AnsiConsole.MarkupLine("[green]Goodbye![/]");
                        return 0;
                }

                AnsiConsole.WriteLine();
            }
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine($"[red]Fatal error: {ex.Message}[/]");
            Logger.Error($"Fatal: {ex}");
            return 1;
        }
    }

    /// <summary>Non-interactive mode via CLI args.</summary>
    private static async Task<int> RunNonInteractiveAsync(string[] args)
    {
        try
        {
            _config = new ConfigManager();
            _httpClient = HttpClientFactory.Create(_config);

            Logger.Initialize(Path.Combine(_config.OutputDirectory, "seckit.log"));

            var targetUrl = "";
            var scanType = "full";
            var outputPath = _config.OutputDirectory;
            var authorized = false;

            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "--scan" when i + 1 < args.Length:
                        targetUrl = args[++i];
                        break;
                    case "--type" when i + 1 < args.Length:
                        scanType = args[++i];
                        break;
                    case "--output" when i + 1 < args.Length:
                        outputPath = args[++i];
                        break;
                    case "--profile" when i + 1 < args.Length:
                        _config.ActiveProfile = args[++i];
                        break;
                    case "--i-am-authorized":
                        authorized = true;
                        break;
                }
            }

            if (string.IsNullOrWhiteSpace(targetUrl))
            {
                Console.Error.WriteLine("Usage: seckit --scan <url> --type <full|vuln|network|ai|map> [--output <path>] [--profile <light|medium|deep>] --i-am-authorized");
                return 1;
            }

            if (!authorized)
            {
                Console.Error.WriteLine("Refusing to scan: pass --i-am-authorized to confirm you have explicit permission to test this target.");
                Console.Error.WriteLine("Unauthorized scanning may be illegal (CFAA, UK Computer Misuse Act, etc.).");
                return 1;
            }

            var report = new SecurityReport
            {
                ScanProfile = _config.ActiveProfile,
                TargetUrls = new List<string> { targetUrl },
                ScanStartTime = DateTime.UtcNow
            };

            Logger.Info($"Starting {scanType} scan of {targetUrl} (profile: {_config.ActiveProfile})");

            switch (scanType.ToLower())
            {
                case "full":
                    await RunVulnScanInternalAsync(targetUrl, report);
                    await RunNetworkScanInternalAsync(targetUrl, report);
                    await RunAiScanInternalAsync(targetUrl, report);
                    await RunSiteMapInternalAsync(targetUrl, report);
                    break;
                case "vuln":
                    await RunVulnScanInternalAsync(targetUrl, report);
                    break;
                case "network":
                    await RunNetworkScanInternalAsync(targetUrl, report);
                    break;
                case "ai":
                    await RunAiScanInternalAsync(targetUrl, report);
                    break;
                case "map":
                    await RunSiteMapInternalAsync(targetUrl, report);
                    break;
                default:
                    Console.Error.WriteLine($"Unknown scan type: {scanType}");
                    return 1;
            }

            report.ScanEndTime = DateTime.UtcNow;
            await ReportGenerator.GenerateAsync(report, outputPath, _config.OutputFormat);

            Logger.Info($"Scan complete. {report.TotalVulnerabilities} findings. Reports saved to {outputPath}");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            return 1;
        }
    }

    #region Interactive Menu Handlers

    private static async Task RunVulnerabilityScanAsync()
    {
        var url = AnsiConsole.Ask<string>("Enter target URL:", _config.TargetUrls.FirstOrDefault() ?? "http://localhost:8080");

        var report = new SecurityReport
        {
            ScanProfile = _config.ActiveProfile,
            TargetUrls = new List<string> { url },
            ScanStartTime = DateTime.UtcNow
        };

        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("Running vulnerability scan...", async ctx =>
            {
                await RunVulnScanInternalAsync(url, report);
            });

        report.ScanEndTime = DateTime.UtcNow;
        await ReportGenerator.GenerateAsync(report, _config.OutputDirectory, _config.OutputFormat);

        AnsiConsole.MarkupLine($"[green]Vulnerability scan complete! {report.TotalVulnerabilities} findings.[/]");
    }

    private static async Task RunNetworkScanAsync()
    {
        var url = AnsiConsole.Ask<string>("Enter target URL:", "https://example.com");

        var report = new SecurityReport
        {
            ScanProfile = _config.ActiveProfile,
            TargetUrls = new List<string> { url },
            ScanStartTime = DateTime.UtcNow
        };

        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("Running network scan...", async ctx =>
            {
                await RunNetworkScanInternalAsync(url, report);
            });

        report.ScanEndTime = DateTime.UtcNow;
        await ReportGenerator.GenerateAsync(report, _config.OutputDirectory, _config.OutputFormat);

        AnsiConsole.MarkupLine($"[green]Network scan complete! {report.TotalVulnerabilities} findings.[/]");
    }

    private static async Task RunAiSecurityTestAsync()
    {
        var url = AnsiConsole.Ask<string>("Enter AI endpoint URL:", "http://localhost:11434/api/chat");

        var report = new SecurityReport
        {
            ScanProfile = _config.ActiveProfile,
            TargetUrls = new List<string> { url },
            ScanStartTime = DateTime.UtcNow
        };

        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("Testing AI security...", async ctx =>
            {
                await RunAiScanInternalAsync(url, report);
            });

        report.ScanEndTime = DateTime.UtcNow;
        await ReportGenerator.GenerateAsync(report, _config.OutputDirectory, _config.OutputFormat);

        AnsiConsole.MarkupLine($"[green]AI security test complete! {report.TotalVulnerabilities} findings.[/]");
    }

    private static async Task RunSiteMapAsync()
    {
        var url = AnsiConsole.Ask<string>("Enter target URL:", "http://localhost:8080");

        var report = new SecurityReport
        {
            ScanProfile = _config.ActiveProfile,
            TargetUrls = new List<string> { url },
            ScanStartTime = DateTime.UtcNow
        };

        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("Mapping site...", async ctx =>
            {
                await RunSiteMapInternalAsync(url, report);
            });

        report.ScanEndTime = DateTime.UtcNow;
        await ReportGenerator.GenerateAsync(report, _config.OutputDirectory, _config.OutputFormat);

        AnsiConsole.MarkupLine($"[green]Site mapping complete! {report.TotalVulnerabilities} findings.[/]");
    }

    private static async Task RunTrafficMonitorAsync()
    {
        var logPath = AnsiConsole.Ask<string>("Enter log file path:", "/var/log/apache2/access.log");

        var monitorChoice = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("Choose mode:")
                .AddChoices(new[] { "Live Monitor (tail -f)", "Attack Detection (analyze file)" }));

        if (monitorChoice.Contains("Live"))
        {
            var monitor = new LiveMonitor(_config);
            await AnsiConsole.Status()
                .Spinner(Spinner.Known.Dots)
                .StartAsync("Starting live monitor...", async ctx =>
                {
                    // Run for a configurable duration
                    await monitor.MonitorAsync(logPath);
                });
        }
        else
        {
            var detector = new AttackDetector(_config);
            await AnsiConsole.Status()
                .Spinner(Spinner.Known.Dots)
                .StartAsync("Analyzing log file...", async ctx =>
                {
                    var result = detector.AnalyzeFile(logPath);
                    ReportGenerator.PrintConsoleSummary(result);
                    var report = new SecurityReport
                    {
                        ScanProfile = _config.ActiveProfile,
                        ScanStartTime = DateTime.UtcNow,
                        ScanEndTime = DateTime.UtcNow
                    };
                    report.ModuleResults.Add(result);
                    report.AllVulnerabilities.AddRange(result.Vulnerabilities);
                    await ReportGenerator.GenerateAsync(report, _config.OutputDirectory, _config.OutputFormat);
                });

            AnsiConsole.MarkupLine("[green]Attack analysis complete![/]");
        }
    }

    private static async Task RunTrafficAnalysisAsync()
    {
        var analysisChoice = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("Select analysis type:")
                .AddChoices(new[] { "GeoIP Mapping (from log file)", "Honeypot Deployment", "Subdomain Enumeration" }));

        if (analysisChoice.Contains("GeoIP"))
        {
            var logPath = AnsiConsole.Ask<string>("Enter log file path:", "/var/log/apache2/access.log");
            var mapper = new GeoIpMapper(HttpClientFactory.CreateSimple(10), _config);

            await AnsiConsole.Status()
                .Spinner(Spinner.Known.Dots)
                .StartAsync("Mapping IPs to locations...", async ctx =>
                {
                    var result = await mapper.AnalyzeAsync(logPath);
                    var report = new SecurityReport
                    {
                        ScanProfile = _config.ActiveProfile,
                        ScanStartTime = DateTime.UtcNow,
                        ScanEndTime = DateTime.UtcNow
                    };
                    report.ModuleResults.Add(result);
                    report.AllVulnerabilities.AddRange(result.Vulnerabilities);
                    await ReportGenerator.GenerateAsync(report, _config.OutputDirectory, _config.OutputFormat);
                });
        }
        else if (analysisChoice.Contains("Honeypot"))
        {
            var port = AnsiConsole.Ask<int>("Enter honeypot port:", 8080);
            var honeypot = new HoneypotManager(_config);
            honeypot.Start(port);

            AnsiConsole.MarkupLine("[yellow]Honeypot running. Press ENTER to stop and view results...[/]");
            Console.ReadLine();
            honeypot.Stop();

            var hpResult = honeypot.GetResults();
            var report = new SecurityReport
            {
                ScanProfile = _config.ActiveProfile,
                ScanStartTime = DateTime.UtcNow,
                ScanEndTime = DateTime.UtcNow
            };
            report.ModuleResults.Add(hpResult);
            report.AllVulnerabilities.AddRange(hpResult.Vulnerabilities);
            await ReportGenerator.GenerateAsync(report, _config.OutputDirectory, _config.OutputFormat);
        }
        else if (analysisChoice.Contains("Subdomain"))
        {
            var domain = AnsiConsole.Ask<string>("Enter target domain:", "example.com");
            var enumerator = new SubdomainEnumerator(_config);

            await AnsiConsole.Status()
                .Spinner(Spinner.Known.Dots)
                .StartAsync("Enumerating subdomains...", async ctx =>
                {
                    var result = await enumerator.EnumerateAsync(domain);
                    var report = new SecurityReport
                    {
                        ScanProfile = _config.ActiveProfile,
                        ScanStartTime = DateTime.UtcNow,
                        ScanEndTime = DateTime.UtcNow
                    };
                    report.ModuleResults.Add(result);
                    report.AllVulnerabilities.AddRange(result.Vulnerabilities);
                    await ReportGenerator.GenerateAsync(report, _config.OutputDirectory, _config.OutputFormat);
                });

            AnsiConsole.MarkupLine("[green]Subdomain enumeration complete![/]");
        }
    }

    private static async Task RunFullSuiteAsync()
    {
        var url = AnsiConsole.Ask<string>("Enter target URL:", _config.TargetUrls.FirstOrDefault() ?? "http://localhost:8080");
        var report = await RunFullSuiteInternalWithProgressAsync(url);

        await ReportGenerator.GenerateAsync(report, _config.OutputDirectory, _config.OutputFormat);

        var table = new Table().Border(TableBorder.Rounded);
        table.AddColumn("Severity");
        table.AddColumn("Count");

        table.AddRow("[red]Critical[/]", report.CriticalCount.ToString());
        table.AddRow("[darkorange]High[/]", report.HighCount.ToString());
        table.AddRow("[yellow]Medium[/]", report.MediumCount.ToString());
        table.AddRow("[green]Low[/]", report.LowCount.ToString());
        table.AddRow("[blue]Info[/]", report.InfoCount.ToString());
        table.AddRow("[bold]TOTAL[/]", report.TotalVulnerabilities.ToString());

        AnsiConsole.Write(table);
        AnsiConsole.MarkupLine($"[green]Full suite complete in {report.TotalDuration.TotalMinutes:F1} minutes![/]");
    }

    #endregion

    #region Internal Scan Methods

    private static async Task RunVulnScanInternalAsync(string url, SecurityReport report)
    {
        var testers = new Dictionary<string, Func<Task<ScanResult>>>
        {
            ["SQL Injection"] = async () =>
            {
                var tester = new SqlInjectionTester(HttpClientFactory.Create(_config), _config);
                return await tester.TestAsync(url);
            },
            ["XSS"] = async () =>
            {
                var tester = new XssTester(HttpClientFactory.Create(_config), _config);
                return await tester.TestAsync(url);
            },
            ["CSRF"] = async () =>
            {
                var tester = new CsrfTester(HttpClientFactory.Create(_config), _config);
                return await tester.TestAsync(url);
            },
            ["SSRF"] = async () =>
            {
                var tester = new SsrfTester(HttpClientFactory.Create(_config), _config);
                return await tester.TestAsync(url);
            },
            ["Path Traversal"] = async () =>
            {
                var tester = new PathTraversalTester(HttpClientFactory.Create(_config), _config);
                return await tester.TestAsync(url);
            },
            ["Auth"] = async () =>
            {
                var tester = new AuthTester(HttpClientFactory.Create(_config), _config);
                return await tester.TestAsync(url);
            },
            ["File Upload"] = async () =>
            {
                var tester = new FileUploadTester(HttpClientFactory.Create(_config), _config);
                return await tester.TestAsync(url);
            }
        };

        foreach (var (name, testFunc) in testers)
        {
            Logger.WriteLine($"\n{new string('═', 50)}", ConsoleColor.DarkGray);
            Logger.WriteLine($"  Running {name} Tester...", ConsoleColor.Cyan);
            var result = await testFunc();
            ReportGenerator.PrintConsoleSummary(result);
            report.ModuleResults.Add(result);
            report.AllVulnerabilities.AddRange(result.Vulnerabilities);
        }
    }

    private static async Task RunNetworkScanInternalAsync(string url, SecurityReport report)
    {
        // Port scanner
        Logger.WriteLine($"\n{new string('═', 50)}", ConsoleColor.DarkGray);
        Logger.WriteLine("  Running Port Scanner...", ConsoleColor.Cyan);
        var portScanner = new PortScanner(_config);
        var portResult = await portScanner.ScanAsync(url);
        ReportGenerator.PrintConsoleSummary(portResult);
        report.ModuleResults.Add(portResult);
        report.AllVulnerabilities.AddRange(portResult.Vulnerabilities);

        // SSL checker (only for HTTPS)
        if (url.StartsWith("https://"))
        {
            Logger.WriteLine($"\n{new string('═', 50)}", ConsoleColor.DarkGray);
            Logger.WriteLine("  Running SSL/TLS Checker...", ConsoleColor.Cyan);
            var sslChecker = new SslChecker(_config);
            var sslResult = await sslChecker.CheckAsync(url);
            ReportGenerator.PrintConsoleSummary(sslResult);
            report.ModuleResults.Add(sslResult);
            report.AllVulnerabilities.AddRange(sslResult.Vulnerabilities);
        }

        // Header analyzer
        Logger.WriteLine($"\n{new string('═', 50)}", ConsoleColor.DarkGray);
        Logger.WriteLine("  Running Header Analyzer...", ConsoleColor.Cyan);
        var headerAnalyzer = new HeaderAnalyzer(HttpClientFactory.Create(_config), _config);
        var headerResult = await headerAnalyzer.AnalyzeAsync(url);
        ReportGenerator.PrintConsoleSummary(headerResult);
        report.ModuleResults.Add(headerResult);
        report.AllVulnerabilities.AddRange(headerResult.Vulnerabilities);
    }

    private static async Task RunAiScanInternalAsync(string url, SecurityReport report)
    {
        Logger.WriteLine($"\n{new string('═', 50)}", ConsoleColor.DarkGray);
        Logger.WriteLine("  Running Prompt Injection Tester...", ConsoleColor.Cyan);
        var piTester = new PromptInjectionTester(HttpClientFactory.Create(_config), _config);
        var piResult = await piTester.TestAsync(url);
        ReportGenerator.PrintConsoleSummary(piResult);
        report.ModuleResults.Add(piResult);
        report.AllVulnerabilities.AddRange(piResult.Vulnerabilities);

        Logger.WriteLine($"\n{new string('═', 50)}", ConsoleColor.DarkGray);
        Logger.WriteLine("  Running Function Call Abuse Tester...", ConsoleColor.Cyan);
        var fcTester = new FunctionCallAbuseTester(HttpClientFactory.Create(_config), _config);
        var fcResult = await fcTester.TestAsync(url);
        ReportGenerator.PrintConsoleSummary(fcResult);
        report.ModuleResults.Add(fcResult);
        report.AllVulnerabilities.AddRange(fcResult.Vulnerabilities);

        Logger.WriteLine($"\n{new string('═', 50)}", ConsoleColor.DarkGray);
        Logger.WriteLine("  Running Data Leakage Tester...", ConsoleColor.Cyan);
        var dlTester = new DataLeakageTester(HttpClientFactory.Create(_config), _config);
        var dlResult = await dlTester.TestAsync(url);
        ReportGenerator.PrintConsoleSummary(dlResult);
        report.ModuleResults.Add(dlResult);
        report.AllVulnerabilities.AddRange(dlResult.Vulnerabilities);
    }

    private static async Task RunSiteMapInternalAsync(string url, SecurityReport report)
    {
        Logger.WriteLine($"\n{new string('═', 50)}", ConsoleColor.DarkGray);
        Logger.WriteLine("  Running Crawler...", ConsoleColor.Cyan);
        var crawler = new Crawler(HttpClientFactory.Create(_config), _config);
        var crawlResult = await crawler.CrawlAsync(url);
        ReportGenerator.PrintConsoleSummary(crawlResult);
        report.ModuleResults.Add(crawlResult);
        report.AllVulnerabilities.AddRange(crawlResult.Vulnerabilities);

        Logger.WriteLine($"\n{new string('═', 50)}", ConsoleColor.DarkGray);
        Logger.WriteLine("  Running Directory Fuzzer...", ConsoleColor.Cyan);
        var fuzzer = new Fuzzer(HttpClientFactory.Create(_config), _config);
        var fuzzResult = await fuzzer.FuzzAsync(url);
        ReportGenerator.PrintConsoleSummary(fuzzResult);
        report.ModuleResults.Add(fuzzResult);
        report.AllVulnerabilities.AddRange(fuzzResult.Vulnerabilities);
    }

    private static async Task<SecurityReport> RunFullSuiteInternalWithProgressAsync(string url)
    {
        var report = new SecurityReport
        {
            ScanProfile = _config.ActiveProfile,
            TargetUrls = new List<string> { url },
            ScanStartTime = DateTime.UtcNow
        };

        await AnsiConsole.Progress()
            .AutoClear(false)
            .Columns(new ProgressColumn[]
            {
                new TaskDescriptionColumn(),
                new ProgressBarColumn(),
                new PercentageColumn(),
                new SpinnerColumn(),
            })
            .StartAsync(async ctx =>
            {
                var vulnTask = ctx.AddTask("[yellow]Vulnerability Scan[/]");
                var netTask = ctx.AddTask("[cyan]Network Scan[/]");
                var aiTask = ctx.AddTask("[magenta]AI Security Test[/]");
                var mapTask = ctx.AddTask("[green]Site Map[/]");

                // Run vulnerability scan
                await RunVulnScanInternalAsync(url, report);
                vulnTask.Value = 100;

                // Run network scan
                await RunNetworkScanInternalAsync(url, report);
                netTask.Value = 100;

                // Run AI security test
                await RunAiScanInternalAsync(url, report);
                aiTask.Value = 100;

                // Run site map
                await RunSiteMapInternalAsync(url, report);
                mapTask.Value = 100;
            });

        report.ScanEndTime = DateTime.UtcNow;
        return report;
    }

    #endregion

    #region Settings

    private static void ShowSettings()
    {
        var profileChoice = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("[yellow]Select scan profile:[/]")
                .AddChoices(new[] { "light", "medium", "deep" }));

        _config.ActiveProfile = profileChoice;

        AnsiConsole.MarkupLine($"[green]Profile set to: {profileChoice}[/]");
        AnsiConsole.MarkupLine($"  Max depth: {_config.MaxDepth}");
        AnsiConsole.MarkupLine($"  Max pages: {_config.MaxPages}");
        AnsiConsole.MarkupLine($"  Timeout: {_config.TimeoutSeconds}s");
        AnsiConsole.MarkupLine($"  Threads: {_config.Threads}");
        AnsiConsole.MarkupLine($"  Port range: {_config.PortRangeStart}-{_config.PortRangeEnd}");
    }

    #endregion
}
