using SecKit.Core;
using SecKit.Models;
using SecKit.Modules.VulnerabilityScanner;
using SecKit.Modules.NetworkScanner;
using SecKit.Modules.AiSecurityTester;
using SecKit.Modules.TrafficMonitor;
using SecKit.Modules.SiteMapper;
using SecKit.Modules.TrafficAnalysis;
using SecKit.Modules.ServerHardening;
using SecKit.Modules.RedTeam;
using SecKit.Modules.CloudAudit;
using SecKit.Modules.Reporting;
using SecKit.Modules.Secrets;
using SecKit.Modules.Crypto;
using SecKit.Modules.Defense;
using SecKit.Modules.Network;

using Spectre.Console;

namespace SecKit;

/// <summary>SecKit — .NET Security Toolkit. Interactive menu-driven CLI for web application security testing.</summary>
public class Program
{
    private static ConfigManager _config = null!;
    private static HttpClient _httpClient = null!;

    // Store the most recent scan results for WAF/IDS rule generation and compliance checks
    private static SecurityReport? _lastScanReport;

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
            AnsiConsole.MarkupLine("[grey]Security Toolkit v2.0.0 — .NET 8[/]");
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
                            "7. Server Hardening (SSH, Filesystem, Users, Processes, Cron, Docker, Firewall)",
                            "8. Red Team Tools (JWT, CORS, Credentials, GraphQL)",
                            "9. Cloud Audit (S3 Buckets, IAM, Security Groups)",
                            "10. Generate WAF/IDS Rules (from last scan results)",
                            "11. Compliance Check (CIS, PCI-DSS, OWASP ASVS)",
                            "12. 💥 Full Suite (All of the above)",
                            "13. ⚙️  Settings",
                            "14. ❌ Exit (v2 modules)",
                            "",
                            "15. Secret Scanning (hardcoded secrets, API keys, credential leaks)",
                            "16. Phishing Detection (SPF, DKIM, DMARC, typosquatting)",
                            "17. Password Audit (strength, entropy, breach check)",
                            "18. Crypto Audit (JWT attacks, hash cracking, certificate analysis)",
                            "19. VirusTotal Scan (malware hash lookup, batch analysis)",
                            "20. YARA Scan (webshell detection, malware patterns)",
                            "21. Ransomware Canary (honeypot files, encryption detection)",
                            "22. Hardware Enumeration (USB, PCI, network interfaces, cables)",
                            "23. Forensics Collection (system snapshot for incident response)",
                            "24. Active Directory Audit (Kerberoasting, delegation, policies)",
                            "25. Enhanced Port Scan (banner grabbing, OS fingerprint, CVE lookup)",
                            "26. Regenerate Reports (from existing JSON reports)",
                            "27. ❌ Exit"
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
                        await RunServerHardeningAsync();
                        break;
                    case string s when s.StartsWith("8"):
                        await RunRedTeamAsync();
                        break;
                    case string s when s.StartsWith("9"):
                        await RunCloudAuditAsync();
                        break;
                    case string s when s.StartsWith("10"):
                        await RunWafIdsGenerationAsync();
                        break;
                    case string s when s.StartsWith("11"):
                        await RunComplianceCheckAsync();
                        break;
                    case string s when s.StartsWith("12"):
                        await RunFullSuiteAsync();
                        break;
                    case string s when s.StartsWith("13"):
                        ShowSettings();
                        break;
                    case string s when s.StartsWith("14"):
                        AnsiConsole.MarkupLine("[grey]Tip: Press Enter to continue exploring v3 modules below...[/]");
                        Console.ReadLine();
                        break;
                    case string s when s.StartsWith("15"):
                        await RunSecretScanAsync();
                        break;
                    case string s when s.StartsWith("16"):
                        await RunPhishingDetectionAsync();
                        break;
                    case string s when s.StartsWith("17"):
                        await RunPasswordAuditAsync();
                        break;
                    case string s when s.StartsWith("18"):
                        await RunCryptoAuditAsync();
                        break;
                    case string s when s.StartsWith("19"):
                        await RunVirusTotalScanAsync();
                        break;
                    case string s when s.StartsWith("20"):
                        await RunYaraScanAsync();
                        break;
                    case string s when s.StartsWith("21"):
                        await RunRansomwareCanaryAsync();
                        break;
                    case string s when s.StartsWith("22"):
                        await RunHardwareEnumAsync();
                        break;
                    case string s when s.StartsWith("23"):
                        await RunForensicsCollectionAsync();
                        break;
                    case string s when s.StartsWith("24"):
                        await RunAdAuditAsync();
                        break;
                    case string s when s.StartsWith("25"):
                        await RunEnhancedPortScanAsync();
                        break;
                    case string s when s.StartsWith("26"):
                        RunRegenerateReports();
                        break;
                    case string s when s.StartsWith("27"):
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

            if (string.IsNullOrWhiteSpace(targetUrl) && scanType is not "rules" and not "compliance" and not "canary" and not "hardware" and not "forensics")
            {
                Console.Error.WriteLine("Usage: seckit --scan <url|path> --type <full|vuln|network|ai|map|server|redteam|cloud|secrets|phishing|password|crypto|virustotal|yara|canary|hardware|forensics|ad|enhanced-port|rules|compliance> [--output <path>] [--profile <light|medium|deep>] --i-am-authorized");
                return 1;
            }

            // Rules and compliance can work from last scan results without a fresh target
            if (!authorized && scanType is not "rules" and not "compliance")
            {
                Console.Error.WriteLine("Refusing to scan: pass --i-am-authorized to confirm you have explicit permission to test this target.");
                Console.Error.WriteLine("Unauthorized scanning may be illegal (CFAA, UK Computer Misuse Act, etc.).");
                return 1;
            }

            var report = new SecurityReport
            {
                ScanProfile = _config.ActiveProfile,
                TargetUrls = string.IsNullOrWhiteSpace(targetUrl) ? new List<string>() : new List<string> { targetUrl },
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
                    await RunServerHardeningInternalAsync(targetUrl, report);
                    await RunRedTeamInternalAsync(targetUrl, report);
                    await RunCloudAuditInternalAsync(targetUrl, report);
                    _lastScanReport = report;
                    break;
                case "vuln":
                    await RunVulnScanInternalAsync(targetUrl, report);
                    _lastScanReport = report;
                    break;
                case "network":
                    await RunNetworkScanInternalAsync(targetUrl, report);
                    _lastScanReport = report;
                    break;
                case "ai":
                    await RunAiScanInternalAsync(targetUrl, report);
                    _lastScanReport = report;
                    break;
                case "map":
                    await RunSiteMapInternalAsync(targetUrl, report);
                    _lastScanReport = report;
                    break;
                case "server":
                    if (!authorized)
                    {
                        Console.Error.WriteLine("Server hardening scan requires authorization (--i-am-authorized).");
                        return 1;
                    }
                    await RunServerHardeningInternalAsync(targetUrl, report);
                    _lastScanReport = report;
                    break;
                case "redteam":
                    await RunRedTeamInternalAsync(targetUrl, report);
                    _lastScanReport = report;
                    break;
                case "cloud":
                    if (!authorized)
                    {
                        Console.Error.WriteLine("Cloud audit requires authorization (--i-am-authorized).");
                        return 1;
                    }
                    await RunCloudAuditInternalAsync(targetUrl, report);
                    _lastScanReport = report;
                    break;
                case "rules":
                    await RunWafIdsGenerationFromLastScanAsync(report);
                    // Rules generation doesn't need the standard report output
                    Logger.Info($"WAF/IDS rules generated to {outputPath}");
                    return 0;
                case "compliance":
                    await RunComplianceCheckFromLastScanAsync(report);
                    Logger.Info($"Compliance report generated to {outputPath}");
                    return 0;
                case "secrets":
                    if (!authorized)
                    {
                        Console.Error.WriteLine("Secret scanning requires authorization (--i-am-authorized).");
                        return 1;
                    }
                    await RunSecretScanInternalAsync(targetUrl, report);
                    _lastScanReport = report;
                    break;
                case "phishing":
                    if (!authorized)
                    {
                        Console.Error.WriteLine("Phishing detection requires authorization (--i-am-authorized).");
                        return 1;
                    }
                    await RunPhishingDetectInternalAsync(targetUrl, report);
                    _lastScanReport = report;
                    break;
                case "password":
                    if (!authorized)
                    {
                        Console.Error.WriteLine("Password audit requires authorization (--i-am-authorized).");
                        return 1;
                    }
                    await RunPasswordAuditInternalAsync(targetUrl, report);
                    _lastScanReport = report;
                    break;
                case "crypto":
                    if (!authorized)
                    {
                        Console.Error.WriteLine("Crypto audit requires authorization (--i-am-authorized).");
                        return 1;
                    }
                    await RunCryptoAuditInternalAsync(targetUrl, report);
                    _lastScanReport = report;
                    break;
                case "virustotal":
                    if (!authorized)
                    {
                        Console.Error.WriteLine("VirusTotal scan requires authorization (--i-am-authorized).");
                        return 1;
                    }
                    await RunVirusTotalScanInternalAsync(targetUrl, report);
                    _lastScanReport = report;
                    break;
                case "yara":
                    if (!authorized)
                    {
                        Console.Error.WriteLine("YARA scan requires authorization (--i-am-authorized).");
                        return 1;
                    }
                    await RunYaraScanInternalAsync(targetUrl, report);
                    _lastScanReport = report;
                    break;
                case "canary":
                    if (!authorized)
                    {
                        Console.Error.WriteLine("Ransomware canary requires authorization (--i-am-authorized).");
                        return 1;
                    }
                    await RunCanaryInternalAsync(targetUrl, report);
                    _lastScanReport = report;
                    break;
                case "hardware":
                    if (!authorized)
                    {
                        Console.Error.WriteLine("Hardware enumeration requires authorization (--i-am-authorized).");
                        return 1;
                    }
                    await RunHardwareEnumInternalAsync(report);
                    _lastScanReport = report;
                    break;
                case "forensics":
                    if (!authorized)
                    {
                        Console.Error.WriteLine("Forensics collection requires authorization (--i-am-authorized).");
                        return 1;
                    }
                    await RunForensicsCollectionInternalAsync(report);
                    _lastScanReport = report;
                    break;
                case "ad":
                    if (!authorized)
                    {
                        Console.Error.WriteLine("AD audit requires authorization (--i-am-authorized).");
                        return 1;
                    }
                    await RunAdAuditInternalAsync(targetUrl, report);
                    _lastScanReport = report;
                    break;
                case "enhanced-port":
                    if (!authorized)
                    {
                        Console.Error.WriteLine("Enhanced port scan requires authorization (--i-am-authorized).");
                        return 1;
                    }
                    await RunEnhancedPortScanInternalAsync(targetUrl, report);
                    _lastScanReport = report;
                    break;
                default:
                    Console.Error.WriteLine($"Unknown scan type: {scanType}");
                    return 1;
            }

            report.ScanEndTime = DateTime.UtcNow;
            _lastScanReport = report;
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
        _lastScanReport = report;
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
        _lastScanReport = report;
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
        _lastScanReport = report;
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
        _lastScanReport = report;
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
                    _lastScanReport = report;
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
                    _lastScanReport = report;
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
            _lastScanReport = report;
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
                    _lastScanReport = report;
                    await ReportGenerator.GenerateAsync(report, _config.OutputDirectory, _config.OutputFormat);
                });

            AnsiConsole.MarkupLine("[green]Subdomain enumeration complete![/]");
        }
    }

    private static async Task RunServerHardeningAsync()
    {
        // Authorization gate for server scans
        AnsiConsole.Write(new Panel(
            "[yellow]Server hardening scans the local system configuration.[/]\n" +
            "This includes SSH, users, filesystem, processes, cron, Docker, and firewall.")
            .Header("[darkorange] SERVER HARDENING [/]")
            .BorderColor(Color.DarkOrange));

        if (!AnsiConsole.Confirm("[yellow]Run server hardening scan?[/]", false))
        {
            AnsiConsole.MarkupLine("[grey]Aborted.[/]");
            return;
        }

        var scanMode = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("Select scan scope:")
                .AddChoices(new[]
                {
                    "Full Hardening Scan (All 7 checks)",
                    "Custom Selection (Choose which checks)"
                }));

        var target = AnsiConsole.Ask<string>("Enter server hostname/IP:", "localhost");
        var scanner = new ServerHardeningScanner(_config);
        var report = new SecurityReport
        {
            ScanProfile = _config.ActiveProfile,
            TargetUrls = new List<string> { target },
            ScanStartTime = DateTime.UtcNow
        };

        if (scanMode.Contains("Full"))
        {
            await AnsiConsole.Status()
                .Spinner(Spinner.Known.Dots)
                .StartAsync("Running full server hardening scan...", async ctx =>
                {
                    var result = await scanner.ScanAllAsync(target);
                    report.ModuleResults.Add(result);
                    report.AllVulnerabilities.AddRange(result.Vulnerabilities);
                });
        }
        else
        {
            // Show sub-menu for picking individual checks
            var subChoices = AnsiConsole.Prompt(
                new MultiSelectionPrompt<string>()
                    .Title("[yellow]Select checks to run (space to toggle, enter to confirm):[/]")
                    .AddChoices(new[]
                    {
                        "SSH Configuration",
                        "Filesystem Permissions",
                        "User Accounts",
                        "Running Processes",
                        "Cron Jobs",
                        "Docker Security",
                        "Firewall Configuration"
                    }));

            await AnsiConsole.Status()
                .Spinner(Spinner.Known.Dots)
                .StartAsync("Running selected hardening checks...", async ctx =>
                {
                    if (subChoices.Contains("SSH Configuration"))
                        AddResults(report, await scanner.CheckSshAsync(target), "SSH Hardening", target);
                    if (subChoices.Contains("Filesystem Permissions"))
                        AddResults(report, await scanner.CheckFilesystemAsync(target), "Filesystem", target);
                    if (subChoices.Contains("User Accounts"))
                        AddResults(report, await scanner.CheckUsersAsync(target), "Users", target);
                    if (subChoices.Contains("Running Processes"))
                        AddResults(report, await scanner.CheckProcessesAsync(target), "Processes", target);
                    if (subChoices.Contains("Cron Jobs"))
                        AddResults(report, await scanner.CheckCronAsync(target), "Cron", target);
                    if (subChoices.Contains("Docker Security"))
                        AddResults(report, await scanner.CheckDockerAsync(target), "Docker", target);
                    if (subChoices.Contains("Firewall Configuration"))
                        AddResults(report, await scanner.CheckFirewallAsync(target), "Firewall", target);
                });
        }

        report.ScanEndTime = DateTime.UtcNow;
        _lastScanReport = report;
        await ReportGenerator.GenerateAsync(report, _config.OutputDirectory, _config.OutputFormat);

        AnsiConsole.MarkupLine($"[green]Server hardening complete! {report.TotalVulnerabilities} findings.[/]");
    }

    private static async Task RunRedTeamAsync()
    {
        var url = AnsiConsole.Ask<string>("Enter target URL:", _config.TargetUrls.FirstOrDefault() ?? "http://localhost:8080");

        var scanMode = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("Select red team scope:")
                .AddChoices(new[]
                {
                    "Full Red Team Scan (All 4 tools)",
                    "Custom Selection (Choose which tools)"
                }));

        var scanner = new RedTeamScanner(HttpClientFactory.Create(_config), _config);
        var report = new SecurityReport
        {
            ScanProfile = _config.ActiveProfile,
            TargetUrls = new List<string> { url },
            ScanStartTime = DateTime.UtcNow
        };

        if (scanMode.Contains("Full"))
        {
            await AnsiConsole.Status()
                .Spinner(Spinner.Known.Dots)
                .StartAsync("Running full red team scan...", async ctx =>
                {
                    var result = await scanner.ScanAllAsync(url);
                    report.ModuleResults.Add(result);
                    report.AllVulnerabilities.AddRange(result.Vulnerabilities);
                });
        }
        else
        {
            var subChoices = AnsiConsole.Prompt(
                new MultiSelectionPrompt<string>()
                    .Title("[yellow]Select tools to run (space to toggle, enter to confirm):[/]")
                    .AddChoices(new[]
                    {
                        "JWT Analysis",
                        "CORS Misconfiguration",
                        "Credential Testing",
                        "GraphQL Introspection"
                    }));

            await AnsiConsole.Status()
                .Spinner(Spinner.Known.Dots)
                .StartAsync("Running selected red team tools...", async ctx =>
                {
                    if (subChoices.Contains("JWT Analysis"))
                        AddResults(report, await scanner.TestJwtAsync(url), "JWT", url);
                    if (subChoices.Contains("CORS Misconfiguration"))
                        AddResults(report, await scanner.TestCorsAsync(url), "CORS", url);
                    if (subChoices.Contains("Credential Testing"))
                        AddResults(report, await scanner.TestCredentialsAsync(url), "Credentials", url);
                    if (subChoices.Contains("GraphQL Introspection"))
                        AddResults(report, await scanner.TestGraphQlAsync(url), "GraphQL", url);
                });
        }

        report.ScanEndTime = DateTime.UtcNow;
        _lastScanReport = report;
        await ReportGenerator.GenerateAsync(report, _config.OutputDirectory, _config.OutputFormat);

        AnsiConsole.MarkupLine($"[green]Red team scan complete! {report.TotalVulnerabilities} findings.[/]");
    }

    private static async Task RunCloudAuditAsync()
    {
        // Authorization gate
        AnsiConsole.Write(new Panel(
            "[yellow]Cloud audit checks cloud resource configurations (S3 buckets, IAM, security groups).[/]\n" +
            "Only audit cloud resources you [bold]own[/] or have [bold]explicit written permission[/] to test.")
            .Header("[blue] CLOUD AUDIT [/]")
            .BorderColor(Color.Blue));

        if (!AnsiConsole.Confirm("[yellow]I confirm I am authorized to audit these cloud resources. Continue?[/]", false))
        {
            AnsiConsole.MarkupLine("[grey]Aborted.[/]");
            return;
        }

        var target = AnsiConsole.Ask<string>("Enter target domain/account:", _config.TargetUrls.FirstOrDefault() ?? "");

        var scanMode = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("Select audit scope:")
                .AddChoices(new[]
                {
                    "Full Cloud Audit (All 3 services)",
                    "Custom Selection (Choose which services)"
                }));

        var scanner = new CloudAuditScanner(_config);
        var report = new SecurityReport
        {
            ScanProfile = _config.ActiveProfile,
            TargetUrls = new List<string> { target },
            ScanStartTime = DateTime.UtcNow
        };

        if (scanMode.Contains("Full"))
        {
            await AnsiConsole.Status()
                .Spinner(Spinner.Known.Dots)
                .StartAsync("Running full cloud audit...", async ctx =>
                {
                    var result = await scanner.ScanAllAsync(target);
                    report.ModuleResults.Add(result);
                    report.AllVulnerabilities.AddRange(result.Vulnerabilities);
                });
        }
        else
        {
            var subChoices = AnsiConsole.Prompt(
                new MultiSelectionPrompt<string>()
                    .Title("[yellow]Select services to audit (space to toggle, enter to confirm):[/]")
                    .AddChoices(new[]
                    {
                        "S3 Buckets",
                        "IAM Roles & Policies",
                        "Security Groups"
                    }));

            await AnsiConsole.Status()
                .Spinner(Spinner.Known.Dots)
                .StartAsync("Running selected cloud audit checks...", async ctx =>
                {
                    if (subChoices.Contains("S3 Buckets"))
                        AddResults(report, await scanner.AuditS3BucketsAsync(target), "S3 Buckets", target);
                    if (subChoices.Contains("IAM Roles & Policies"))
                        AddResults(report, await scanner.AuditIamAsync(target), "IAM", target);
                    if (subChoices.Contains("Security Groups"))
                        AddResults(report, await scanner.AuditSecurityGroupsAsync(target), "Security Groups", target);
                });
        }

        report.ScanEndTime = DateTime.UtcNow;
        _lastScanReport = report;
        await ReportGenerator.GenerateAsync(report, _config.OutputDirectory, _config.OutputFormat);

        AnsiConsole.MarkupLine($"[green]Cloud audit complete! {report.TotalVulnerabilities} findings.[/]");
    }

    private static async Task RunSecretScanAsync()
    {
        var path = AnsiConsole.Ask<string>("Enter path (file or directory) to scan for secrets:", "./");

        var scanner = new SecretScanner(_config);
        var report = new SecurityReport
        {
            ScanProfile = _config.ActiveProfile,
            TargetUrls = new List<string> { path },
            ScanStartTime = DateTime.UtcNow
        };

        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("Scanning for hardcoded secrets...", async ctx =>
            {
                var result = await scanner.ScanAsync(path);
                report.ModuleResults.Add(result);
                report.AllVulnerabilities.AddRange(result.Vulnerabilities);
            });

        report.ScanEndTime = DateTime.UtcNow;
        _lastScanReport = report;
        await ReportGenerator.GenerateAsync(report, _config.OutputDirectory, _config.OutputFormat);

        AnsiConsole.MarkupLine($"[green]Secret scan complete! {report.TotalVulnerabilities} findings.[/]");
    }

    private static async Task RunPhishingDetectionAsync()
    {
        var domain = AnsiConsole.Ask<string>("Enter domain to check:", "example.com");

        var detector = new PhishingDetector(_config);
        var report = new SecurityReport
        {
            ScanProfile = _config.ActiveProfile,
            TargetUrls = new List<string> { domain },
            ScanStartTime = DateTime.UtcNow
        };

        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("Checking anti-phishing protections...", async ctx =>
            {
                var result = await detector.ScanAsync(domain);
                report.ModuleResults.Add(result);
                report.AllVulnerabilities.AddRange(result.Vulnerabilities);
            });

        report.ScanEndTime = DateTime.UtcNow;
        _lastScanReport = report;
        await ReportGenerator.GenerateAsync(report, _config.OutputDirectory, _config.OutputFormat);

        AnsiConsole.MarkupLine($"[green]Phishing detection complete! {report.TotalVulnerabilities} findings.[/]");
    }

    private static async Task RunPasswordAuditAsync()
    {
        var target = AnsiConsole.Ask<string>("Enter password, file path, or directory to audit:", "");

        if (string.IsNullOrWhiteSpace(target))
        {
            // Interactive password entry
            target = AnsiConsole.Prompt(
                new TextPrompt<string>("Enter password to audit:")
                    .Secret());
        }

        var auditor = new PasswordAuditor(HttpClientFactory.CreateSimple(10), _config);
        var report = new SecurityReport
        {
            ScanProfile = _config.ActiveProfile,
            TargetUrls = new List<string> { "password-audit" },
            ScanStartTime = DateTime.UtcNow
        };

        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("Auditing password strength...", async ctx =>
            {
                var result = await auditor.ScanAsync(target);
                report.ModuleResults.Add(result);
                report.AllVulnerabilities.AddRange(result.Vulnerabilities);
            });

        report.ScanEndTime = DateTime.UtcNow;
        _lastScanReport = report;
        await ReportGenerator.GenerateAsync(report, _config.OutputDirectory, _config.OutputFormat);

        AnsiConsole.MarkupLine($"[green]Password audit complete! {report.TotalVulnerabilities} findings.[/]");
    }

    private static async Task RunCryptoAuditAsync()
    {
        var url = AnsiConsole.Ask<string>("Enter target URL:", "https://example.com");

        var auditor = new CryptoAuditor(HttpClientFactory.Create(_config), _config);
        var report = new SecurityReport
        {
            ScanProfile = _config.ActiveProfile,
            TargetUrls = new List<string> { url },
            ScanStartTime = DateTime.UtcNow
        };

        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("Auditing crypto implementations...", async ctx =>
            {
                var result = await auditor.ScanAsync(url);
                report.ModuleResults.Add(result);
                report.AllVulnerabilities.AddRange(result.Vulnerabilities);
            });

        report.ScanEndTime = DateTime.UtcNow;
        _lastScanReport = report;
        await ReportGenerator.GenerateAsync(report, _config.OutputDirectory, _config.OutputFormat);

        AnsiConsole.MarkupLine($"[green]Crypto audit complete! {report.TotalVulnerabilities} findings.[/]");
    }

    private static async Task RunVirusTotalScanAsync()
    {
        var target = AnsiConsole.Ask<string>("Enter file path, directory, or SHA-256 hash to check:", "./");

        var scanner = new VirusTotalScanner(HttpClientFactory.CreateSimple(10), _config);
        var report = new SecurityReport
        {
            ScanProfile = _config.ActiveProfile,
            TargetUrls = new List<string> { target },
            ScanStartTime = DateTime.UtcNow
        };

        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("Querying VirusTotal...", async ctx =>
            {
                var result = await scanner.ScanAsync(target);
                report.ModuleResults.Add(result);
                report.AllVulnerabilities.AddRange(result.Vulnerabilities);
            });

        report.ScanEndTime = DateTime.UtcNow;
        _lastScanReport = report;
        await ReportGenerator.GenerateAsync(report, _config.OutputDirectory, _config.OutputFormat);

        AnsiConsole.MarkupLine($"[green]VirusTotal scan complete! {report.TotalVulnerabilities} findings.[/]");
    }

    private static async Task RunYaraScanAsync()
    {
        var path = AnsiConsole.Ask<string>("Enter file or directory path to scan:", "./");

        var scanner = new YaraScanner(_config);
        var report = new SecurityReport
        {
            ScanProfile = _config.ActiveProfile,
            TargetUrls = new List<string> { path },
            ScanStartTime = DateTime.UtcNow
        };

        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("Running YARA pattern scan...", async ctx =>
            {
                var result = await scanner.ScanAsync(path);
                report.ModuleResults.Add(result);
                report.AllVulnerabilities.AddRange(result.Vulnerabilities);
            });

        report.ScanEndTime = DateTime.UtcNow;
        _lastScanReport = report;
        await ReportGenerator.GenerateAsync(report, _config.OutputDirectory, _config.OutputFormat);

        AnsiConsole.MarkupLine($"[green]YARA scan complete! {report.TotalVulnerabilities} findings.[/]");
    }

    private static async Task RunRansomwareCanaryAsync()
    {
        AnsiConsole.Write(new Panel(
            "[yellow]Ransomware Canary deploys honeypot files to detect unauthorized modification or encryption.[/]\n" +
            "Choose to deploy new canaries or verify existing ones.")
            .Header("[darkorange] RANSOMWARE CANARY [/]")
            .BorderColor(Color.DarkOrange));

        var action = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("Select action:")
                .AddChoices(new[] { "Deploy canaries to temp directory", "Deploy canaries to custom directory", "Verify existing canaries" }));

        var canary = new RansomwareCanary();
        var report = new SecurityReport
        {
            ScanProfile = _config.ActiveProfile,
            ScanStartTime = DateTime.UtcNow
        };

        string? customPath = null;
        if (action.Contains("custom"))
        {
            customPath = AnsiConsole.Ask<string>("Enter directory to deploy canaries:", "/tmp/seckit-canaries");
        }

        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("Managing ransomware canaries...", async ctx =>
            {
                var result = await canary.ScanAsync(customPath ?? string.Empty);
                report.TargetUrls = new List<string> { result.TargetUrl };
                report.ModuleResults.Add(result);
                report.AllVulnerabilities.AddRange(result.Vulnerabilities);
            });

        report.ScanEndTime = DateTime.UtcNow;
        _lastScanReport = report;
        await ReportGenerator.GenerateAsync(report, _config.OutputDirectory, _config.OutputFormat);

        AnsiConsole.MarkupLine($"[green]Ransomware canary check complete! {report.TotalVulnerabilities} findings.[/]");
    }

    private static async Task RunHardwareEnumAsync()
    {
        AnsiConsole.Write(new Panel(
            "[yellow]Hardware enumeration scans local hardware: USB devices, PCI devices,\nn" +
            "network interfaces, disk drives, and cable status.[/]")
            .Header("[steelblue] HARDWARE ENUMERATION [/]")
            .BorderColor(Color.SteelBlue));

        if (!AnsiConsole.Confirm("[yellow]Run hardware enumeration on this system?[/]", false))
        {
            AnsiConsole.MarkupLine("[grey]Aborted.[/]");
            return;
        }

        var enumerator = new HardwareEnumerator();
        var report = new SecurityReport
        {
            ScanProfile = _config.ActiveProfile,
            ScanStartTime = DateTime.UtcNow
        };

        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("Enumerating hardware...", async ctx =>
            {
                var result = await enumerator.ScanAsync(Environment.MachineName);
                report.TargetUrls = new List<string> { result.TargetUrl };
                report.ModuleResults.Add(result);
                report.AllVulnerabilities.AddRange(result.Vulnerabilities);
            });

        report.ScanEndTime = DateTime.UtcNow;
        _lastScanReport = report;
        await ReportGenerator.GenerateAsync(report, _config.OutputDirectory, _config.OutputFormat);

        AnsiConsole.MarkupLine($"[green]Hardware enumeration complete! {report.TotalVulnerabilities} findings.[/]");
    }

    private static async Task RunForensicsCollectionAsync()
    {
        AnsiConsole.Write(new Panel(
            "[yellow]Forensics collection gathers system snapshots for incident response:\nn" +
            "processes, network connections, users, startup items, browser artifacts.[/]")
            .Header("[blue] FORENSICS COLLECTION [/]")
            .BorderColor(Color.Blue));

        if (!AnsiConsole.Confirm("[yellow]Collect forensic evidence from this system?[/]", false))
        {
            AnsiConsole.MarkupLine("[grey]Aborted.[/]");
            return;
        }

        var collector = new ForensicsCollector();
        var report = new SecurityReport
        {
            ScanProfile = _config.ActiveProfile,
            ScanStartTime = DateTime.UtcNow
        };

        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("Collecting forensic evidence...", async ctx =>
            {
                var result = await collector.ScanAsync(Environment.MachineName);
                report.TargetUrls = new List<string> { result.TargetUrl };
                report.ModuleResults.Add(result);
                report.AllVulnerabilities.AddRange(result.Vulnerabilities);
            });

        report.ScanEndTime = DateTime.UtcNow;
        _lastScanReport = report;
        await ReportGenerator.GenerateAsync(report, _config.OutputDirectory, _config.OutputFormat);

        AnsiConsole.MarkupLine($"[green]Forensics collection complete! {report.TotalVulnerabilities} findings.[/]");
    }

    private static async Task RunAdAuditAsync()
    {
        AnsiConsole.Write(new Panel(
            "[yellow]Active Directory audit checks Kerberoasting, delegation, password policies,\nn" +
            "privileged groups, domain controller security, and NTLM usage.[/]")
            .Header("[purple] ACTIVE DIRECTORY AUDIT [/]")
            .BorderColor(Color.Purple));

        if (!AnsiConsole.Confirm("[yellow]Run Active Directory audit? Only works on domain-joined Windows systems. Continue?[/]", false))
        {
            AnsiConsole.MarkupLine("[grey]Aborted.[/]");
            return;
        }

        var domain = AnsiConsole.Ask<string>("Enter domain name (leave blank for current domain):", "");
        if (string.IsNullOrWhiteSpace(domain)) domain = null!;

        var auditor = new AdAuditor(_config);
        var report = new SecurityReport
        {
            ScanProfile = _config.ActiveProfile,
            ScanStartTime = DateTime.UtcNow
        };

        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("Auditing Active Directory...", async ctx =>
            {
                var result = domain != null ? await auditor.ScanAsync(domain) : await auditor.ScanAsync();
                report.TargetUrls = new List<string> { result.TargetUrl };
                report.ModuleResults.Add(result);
                report.AllVulnerabilities.AddRange(result.Vulnerabilities);
            });

        report.ScanEndTime = DateTime.UtcNow;
        _lastScanReport = report;
        await ReportGenerator.GenerateAsync(report, _config.OutputDirectory, _config.OutputFormat);

        AnsiConsole.MarkupLine($"[green]AD audit complete! {report.TotalVulnerabilities} findings.[/]");
    }

    private static async Task RunEnhancedPortScanAsync()
    {
        var target = AnsiConsole.Ask<string>("Enter target host (IP or hostname):", "localhost");

        var scanner = new EnhancedPortScanner(HttpClientFactory.CreateSimple(10), _config);
        var report = new SecurityReport
        {
            ScanProfile = _config.ActiveProfile,
            TargetUrls = new List<string> { target },
            ScanStartTime = DateTime.UtcNow
        };

        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("Running enhanced port scan...", async ctx =>
            {
                var result = await scanner.ScanAsync(target);
                report.ModuleResults.Add(result);
                report.AllVulnerabilities.AddRange(result.Vulnerabilities);
            });

        report.ScanEndTime = DateTime.UtcNow;
        _lastScanReport = report;
        await ReportGenerator.GenerateAsync(report, _config.OutputDirectory, _config.OutputFormat);

        var openPorts = report.AllVulnerabilities.Count(v => v.Type == "Open Port");
        AnsiConsole.MarkupLine($"[green]Enhanced port scan complete! {openPorts} open ports found. {report.TotalVulnerabilities} total findings.[/]");
    }

    private static async Task RunWafIdsGenerationAsync()
    {
        if (_lastScanReport == null || _lastScanReport.AllVulnerabilities.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No previous scan results available. Run a vulnerability or network scan first.[/]");
            return;
        }

        var vulns = _lastScanReport.AllVulnerabilities;

        AnsiConsole.MarkupLine($"[grey]Generating WAF/IDS rules from {vulns.Count} findings...[/]");

        var rulesChoice = AnsiConsole.Prompt(
            new MultiSelectionPrompt<string>()
                .Title("[yellow]Select rule types to generate:[/]")
                .AddChoices(new[]
                {
                    "ModSecurity WAF Rules",
                    "Cloudflare WAF Rules (JSON)",
                    "nginx Rate-Limit Config",
                    "Snort IDS Rules",
                    "Suricata IDS Rules"
                }));

        if (rulesChoice.Any(c => c.Contains("ModSecurity") || c.Contains("Cloudflare") || c.Contains("nginx")))
        {
            var wafGen = new WafGenerator(_config.OutputDirectory);
            var wafReport = await wafGen.GenerateAsync(vulns);

            AnsiConsole.MarkupLine("[green]WAF rules generated:[/]");
            if (rulesChoice.Any(c => c.Contains("ModSecurity")))
                AnsiConsole.MarkupLine($"  ModSecurity: {wafReport.ModSecurityPath} ({wafReport.ModSecurityRuleCount} rules)");
            if (rulesChoice.Any(c => c.Contains("Cloudflare")))
                AnsiConsole.MarkupLine($"  Cloudflare:  {wafReport.CloudflarePath} ({wafReport.CloudflareRuleCount} rules)");
            if (rulesChoice.Any(c => c.Contains("nginx")))
                AnsiConsole.MarkupLine($"  nginx:       {wafReport.NginxPath}");
        }

        if (rulesChoice.Any(c => c.Contains("Snort") || c.Contains("Suricata")))
        {
            var idsGen = new IdsExporter(_config.OutputDirectory);
            var idsReport = await idsGen.GenerateAsync(vulns);

            AnsiConsole.MarkupLine("[green]IDS rules generated:[/]");
            if (rulesChoice.Any(c => c.Contains("Snort")))
                AnsiConsole.MarkupLine($"  Snort:    {idsReport.SnortPath} ({idsReport.SnortRuleCount} rules)");
            if (rulesChoice.Any(c => c.Contains("Suricata")))
                AnsiConsole.MarkupLine($"  Suricata: {idsReport.SuricataPath} ({idsReport.SuricataRuleCount} rules)");
        }

        AnsiConsole.MarkupLine("[green]WAF/IDS rule generation complete![/]");
    }

    private static async Task RunComplianceCheckAsync()
    {
        if (_lastScanReport == null || _lastScanReport.AllVulnerabilities.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No previous scan results available. Run a scan first to generate compliance mappings.[/]");
            return;
        }

        var vulns = _lastScanReport.AllVulnerabilities;

        AnsiConsole.MarkupLine($"[grey]Running compliance check against {vulns.Count} findings...[/]");

        var frameworksChoice = AnsiConsole.Prompt(
            new MultiSelectionPrompt<string>()
                .Title("[yellow]Select compliance frameworks:[/]")
                .AddChoices(new[]
                {
                    "CIS Benchmarks",
                    "PCI-DSS v4.0",
                    "OWASP ASVS"
                }));

        var checker = new ComplianceChecker(_config.OutputDirectory);
        var report = await checker.CheckAsync(vulns);

        // Display summary
        var table = new Table().Border(TableBorder.Rounded);
        table.AddColumn("Framework");
        table.AddColumn("Passed");
        table.AddColumn("Failed");
        table.AddColumn("Pass Rate");

        if (frameworksChoice.Contains("CIS Benchmarks"))
        {
            table.AddRow(
                "[cyan]CIS Benchmarks[/]",
                $"[green]{report.CisPassed}[/]",
                $"[red]{report.CisFailed}[/]",
                $"[yellow]{report.CisPassRate:P0}[/]");
        }
        if (frameworksChoice.Contains("PCI-DSS"))
        {
            table.AddRow(
                "[cyan]PCI-DSS v4.0[/]",
                $"[green]{report.PciPassed}[/]",
                $"[red]{report.PciFailed}[/]",
                $"[yellow]{report.PciPassRate:P0}[/]");
        }
        if (frameworksChoice.Contains("OWASP"))
        {
            table.AddRow(
                "[cyan]OWASP ASVS[/]",
                $"[green]{report.OwaspPassed}[/]",
                $"[red]{report.OwaspFailed}[/]",
                $"[yellow]{report.OwaspPassRate:P0}[/]");
        }

        table.AddRow(
            "[bold]OVERALL[/]",
            $"[green]{report.TotalPassed}[/]",
            $"[red]{report.TotalControls - report.TotalPassed}[/]",
            $"[bold yellow]{report.OverallPassRate:P0}[/]");

        AnsiConsole.Write(table);
        AnsiConsole.MarkupLine($"[green]Compliance report saved to: {report.ReportPath}[/]");
        AnsiConsole.MarkupLine($"[grey]JSON report: {report.JsonPath}[/]");
    }

    private static async Task RunFullSuiteAsync()
    {
        var url = AnsiConsole.Ask<string>("Enter target URL:", _config.TargetUrls.FirstOrDefault() ?? "http://localhost:8080");
        var report = await RunFullSuiteInternalWithProgressAsync(url);

        _lastScanReport = report;
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

    #region Rules and Compliance helpers (from last scan)

    private static async Task RunWafIdsGenerationFromLastScanAsync(SecurityReport report)
    {
        var vulns = report.AllVulnerabilities;
        if (vulns.Count == 0 && _lastScanReport != null)
            vulns = _lastScanReport.AllVulnerabilities;

        if (vulns.Count == 0)
        {
            Logger.Warning("No findings to generate rules from.");
            return;
        }

        var wafGen = new WafGenerator(_config.OutputDirectory);
        await wafGen.GenerateAsync(vulns);

        var idsGen = new IdsExporter(_config.OutputDirectory);
        await idsGen.GenerateAsync(vulns);
    }

    private static async Task RunComplianceCheckFromLastScanAsync(SecurityReport report)
    {
        var vulns = report.AllVulnerabilities;
        if (vulns.Count == 0 && _lastScanReport != null)
            vulns = _lastScanReport.AllVulnerabilities;

        if (vulns.Count == 0)
        {
            Logger.Warning("No findings to run compliance check against.");
            return;
        }

        var checker = new ComplianceChecker(_config.OutputDirectory);
        await checker.CheckAsync(vulns);
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

    private static async Task RunServerHardeningInternalAsync(string target, SecurityReport report)
    {
        var scanner = new ServerHardeningScanner(_config);

        Logger.WriteLine($"\n{new string('═', 50)}", ConsoleColor.DarkGray);
        Logger.WriteLine("  Running Server Hardening Scan...", ConsoleColor.Cyan);

        var result = await scanner.ScanAllAsync(target);
        ReportGenerator.PrintConsoleSummary(result);
        report.ModuleResults.Add(result);
        report.AllVulnerabilities.AddRange(result.Vulnerabilities);
    }

    private static async Task RunRedTeamInternalAsync(string url, SecurityReport report)
    {
        var scanner = new RedTeamScanner(HttpClientFactory.Create(_config), _config);

        Logger.WriteLine($"\n{new string('═', 50)}", ConsoleColor.DarkGray);
        Logger.WriteLine("  Running Red Team Scan...", ConsoleColor.Cyan);

        var result = await scanner.ScanAllAsync(url);
        ReportGenerator.PrintConsoleSummary(result);
        report.ModuleResults.Add(result);
        report.AllVulnerabilities.AddRange(result.Vulnerabilities);
    }

    private static async Task RunCloudAuditInternalAsync(string target, SecurityReport report)
    {
        var scanner = new CloudAuditScanner(_config);

        Logger.WriteLine($"\n{new string('═', 50)}", ConsoleColor.DarkGray);
        Logger.WriteLine("  Running Cloud Audit...", ConsoleColor.Cyan);

        var result = await scanner.ScanAllAsync(target);
        ReportGenerator.PrintConsoleSummary(result);
        report.ModuleResults.Add(result);
        report.AllVulnerabilities.AddRange(result.Vulnerabilities);
    }

    // --- v3 New Module Internal Methods ---

    private static async Task RunSecretScanInternalAsync(string target, SecurityReport report)
    {
        Logger.WriteLine($"\n{new string('═', 50)}", ConsoleColor.DarkGray);
        Logger.WriteLine("  Running Secret Scanner...", ConsoleColor.Cyan);

        var scanner = new SecretScanner(_config);
        var result = await scanner.ScanAsync(target);
        ReportGenerator.PrintConsoleSummary(result);
        report.ModuleResults.Add(result);
        report.AllVulnerabilities.AddRange(result.Vulnerabilities);
    }

    private static async Task RunPhishingDetectInternalAsync(string target, SecurityReport report)
    {
        Logger.WriteLine($"\n{new string('═', 50)}", ConsoleColor.DarkGray);
        Logger.WriteLine("  Running Phishing Detection...", ConsoleColor.Cyan);

        var detector = new PhishingDetector(_config);
        var result = await detector.ScanAsync(target);
        ReportGenerator.PrintConsoleSummary(result);
        report.ModuleResults.Add(result);
        report.AllVulnerabilities.AddRange(result.Vulnerabilities);
    }

    private static async Task RunPasswordAuditInternalAsync(string target, SecurityReport report)
    {
        Logger.WriteLine($"\n{new string('═', 50)}", ConsoleColor.DarkGray);
        Logger.WriteLine("  Running Password Audit...", ConsoleColor.Cyan);

        var auditor = new PasswordAuditor(HttpClientFactory.CreateSimple(10), _config);
        var result = await auditor.ScanAsync(target);
        ReportGenerator.PrintConsoleSummary(result);
        report.ModuleResults.Add(result);
        report.AllVulnerabilities.AddRange(result.Vulnerabilities);
    }

    private static async Task RunCryptoAuditInternalAsync(string target, SecurityReport report)
    {
        Logger.WriteLine($"\n{new string('═', 50)}", ConsoleColor.DarkGray);
        Logger.WriteLine("  Running Crypto Audit...", ConsoleColor.Cyan);

        var auditor = new CryptoAuditor(HttpClientFactory.Create(_config), _config);
        var result = await auditor.ScanAsync(target);
        ReportGenerator.PrintConsoleSummary(result);
        report.ModuleResults.Add(result);
        report.AllVulnerabilities.AddRange(result.Vulnerabilities);
    }

    private static async Task RunVirusTotalScanInternalAsync(string target, SecurityReport report)
    {
        Logger.WriteLine($"\n{new string('═', 50)}", ConsoleColor.DarkGray);
        Logger.WriteLine("  Running VirusTotal Scan...", ConsoleColor.Cyan);

        var scanner = new VirusTotalScanner(HttpClientFactory.CreateSimple(10), _config);
        var result = await scanner.ScanAsync(target);
        ReportGenerator.PrintConsoleSummary(result);
        report.ModuleResults.Add(result);
        report.AllVulnerabilities.AddRange(result.Vulnerabilities);
    }

    private static async Task RunYaraScanInternalAsync(string target, SecurityReport report)
    {
        Logger.WriteLine($"\n{new string('═', 50)}", ConsoleColor.DarkGray);
        Logger.WriteLine("  Running YARA Scan...", ConsoleColor.Cyan);

        var scanner = new YaraScanner(_config);
        var result = await scanner.ScanAsync(target);
        ReportGenerator.PrintConsoleSummary(result);
        report.ModuleResults.Add(result);
        report.AllVulnerabilities.AddRange(result.Vulnerabilities);
    }

    private static async Task RunCanaryInternalAsync(string target, SecurityReport report)
    {
        Logger.WriteLine($"\n{new string('═', 50)}", ConsoleColor.DarkGray);
        Logger.WriteLine("  Running Ransomware Canary...", ConsoleColor.Cyan);

        var canary = new RansomwareCanary();
        var result = await canary.ScanAsync(string.IsNullOrWhiteSpace(target) ? target : target);
        report.TargetUrls.Add(result.TargetUrl);
        ReportGenerator.PrintConsoleSummary(result);
        report.ModuleResults.Add(result);
        report.AllVulnerabilities.AddRange(result.Vulnerabilities);
    }

    private static async Task RunHardwareEnumInternalAsync(SecurityReport report)
    {
        Logger.WriteLine($"\n{new string('═', 50)}", ConsoleColor.DarkGray);
        Logger.WriteLine("  Running Hardware Enumeration...", ConsoleColor.Cyan);

        var enumerator = new HardwareEnumerator();
        var result = await enumerator.ScanAsync(Environment.MachineName);
        report.TargetUrls.Add(result.TargetUrl);
        ReportGenerator.PrintConsoleSummary(result);
        report.ModuleResults.Add(result);
        report.AllVulnerabilities.AddRange(result.Vulnerabilities);
    }

    private static async Task RunForensicsCollectionInternalAsync(SecurityReport report)
    {
        Logger.WriteLine($"\n{new string('═', 50)}", ConsoleColor.DarkGray);
        Logger.WriteLine("  Running Forensics Collection...", ConsoleColor.Cyan);

        var collector = new ForensicsCollector();
        var result = await collector.ScanAsync(Environment.MachineName);
        report.TargetUrls.Add(result.TargetUrl);
        ReportGenerator.PrintConsoleSummary(result);
        report.ModuleResults.Add(result);
        report.AllVulnerabilities.AddRange(result.Vulnerabilities);
    }

    private static async Task RunAdAuditInternalAsync(string target, SecurityReport report)
    {
        Logger.WriteLine($"\n{new string('═', 50)}", ConsoleColor.DarkGray);
        Logger.WriteLine("  Running Active Directory Audit...", ConsoleColor.Cyan);

        var auditor = new AdAuditor(_config);
        var result = string.IsNullOrWhiteSpace(target) ? await auditor.ScanAsync() : await auditor.ScanAsync(target);
        report.TargetUrls.Add(result.TargetUrl);
        ReportGenerator.PrintConsoleSummary(result);
        report.ModuleResults.Add(result);
        report.AllVulnerabilities.AddRange(result.Vulnerabilities);
    }

    private static async Task RunEnhancedPortScanInternalAsync(string target, SecurityReport report)
    {
        Logger.WriteLine($"\n{new string('═', 50)}", ConsoleColor.DarkGray);
        Logger.WriteLine("  Running Enhanced Port Scan...", ConsoleColor.Cyan);

        var scanner = new EnhancedPortScanner(HttpClientFactory.CreateSimple(10), _config);
        var result = await scanner.ScanAsync(target);
        ReportGenerator.PrintConsoleSummary(result);
        report.ModuleResults.Add(result);
        report.AllVulnerabilities.AddRange(result.Vulnerabilities);
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
                var serverTask = ctx.AddTask("[darkorange]Server Hardening[/]");
                var redTask = ctx.AddTask("[red]Red Team[/]");
                var cloudTask = ctx.AddTask("[blue]Cloud Audit[/]");
                var secretTask = ctx.AddTask("[yellow]Secret Scan[/]");
                var cryptoTask = ctx.AddTask("[cyan]Crypto Audit[/]");
                var yaraTask = ctx.AddTask("[red]YARA Scan[/]");
                var canaryTask = ctx.AddTask("[darkorange]Ransomware Canary[/]");
                var hwTask = ctx.AddTask("[steelblue]Hardware Enum[/]");
                var forensicTask = ctx.AddTask("[blue]Forensics[/]");
                var adTask = ctx.AddTask("[purple]AD Audit[/]");
                var portTask = ctx.AddTask("[green]Enhanced Port Scan[/]");

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

                // Run server hardening
                await RunServerHardeningInternalAsync(url, report);
                serverTask.Value = 100;

                // Run red team
                await RunRedTeamInternalAsync(url, report);
                redTask.Value = 100;

                // Run cloud audit
                await RunCloudAuditInternalAsync(url, report);
                cloudTask.Value = 100;

                // v3: Secret scan
                await RunSecretScanInternalAsync(url, report);
                secretTask.Value = 100;

                // v3: Crypto audit
                await RunCryptoAuditInternalAsync(url, report);
                cryptoTask.Value = 100;

                // v3: YARA scan (scan the codebase directory)
                try
                {
                    await RunYaraScanInternalAsync(Directory.GetCurrentDirectory(), report);
                }
                catch { /* YARA scan may fail on non-filesystem targets */ }
                yaraTask.Value = 100;

                // v3: Ransomware canary
                await RunCanaryInternalAsync("", report);
                canaryTask.Value = 100;

                // v3: Hardware enumeration
                await RunHardwareEnumInternalAsync(report);
                hwTask.Value = 100;

                // v3: Forensics
                await RunForensicsCollectionInternalAsync(report);
                forensicTask.Value = 100;

                // v3: AD audit
                try
                {
                    await RunAdAuditInternalAsync("", report);
                }
                catch { /* AD audit requires domain-joined Windows */ }
                adTask.Value = 100;

                // v3: Enhanced port scan
                await RunEnhancedPortScanInternalAsync(url, report);
                portTask.Value = 100;
            });

        report.ScanEndTime = DateTime.UtcNow;
        return report;
    }

    /// <summary>Helper to add a list of vulnerabilities to a report as a module result.</summary>
    private static void AddResults(SecurityReport report, List<Vulnerability> vulns, string moduleName, string targetUrl)
    {
        var result = new ScanResult
        {
            ModuleName = moduleName,
            TargetUrl = targetUrl,
            StartTime = DateTime.UtcNow,
            EndTime = DateTime.UtcNow,
            Completed = true
        };
        result.Vulnerabilities.AddRange(vulns);
        report.ModuleResults.Add(result);
        report.AllVulnerabilities.AddRange(vulns);
    }

    #endregion

    private static void RunRegenerateReports()
    {
        var dir = AnsiConsole.Ask<string>("Enter directory containing JSON report files:", _config.OutputDirectory);
        var count = ReportGenerator.Regenerate(dir);
        AnsiConsole.MarkupLine($"[green]Regenerated {count} HTML reports.[/]");
    }

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
