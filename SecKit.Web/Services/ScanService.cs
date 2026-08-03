using SecKit.Core;
using SecKit.Models;
using SecKit.Modules.VulnerabilityScanner;
using SecKit.Modules.NetworkScanner;
using SecKit.Modules.AiSecurityTester;
using SecKit.Modules.SiteMapper;
using System.Collections.Concurrent;
using System.Text.Json;

namespace SecKit.Web.Services;

/// <summary>Orchestrates scans, tracks state, and provides progress to the UI.</summary>
public class ScanService
{
    private readonly ConfigManager _config;
    private readonly ConcurrentDictionary<string, ScanJob> _scans = new();
    private readonly List<ScanHistoryItem> _history = new();

    public ScanService(ConfigManager config)
    {
        _config = config;

        // Load existing reports into history
        LoadHistoryFromDisk();
    }

    /// <summary>Current list of recent scan history items.</summary>
    public IReadOnlyList<ScanHistoryItem> RecentHistory => _history.AsReadOnly();

    /// <summary>Gets a scan job by ID.</summary>
    public ScanJob? GetScan(string jobId) =>
        _scans.TryGetValue(jobId, out var job) ? job : null;

    /// <summary>Gets all active scan jobs.</summary>
    public IEnumerable<ScanJob> ActiveScans => _scans.Values;

    /// <summary>Gets quick stats for the dashboard.</summary>
    public DashboardStats GetStats()
    {
        var allVulns = _history.SelectMany(h => h.AllVulnerabilities).ToList();
        return new DashboardStats
        {
            TotalScans = _history.Count,
            TotalVulnerabilities = allVulns.Count,
            CriticalCount = allVulns.Count(v => v.Severity == "Critical"),
            HighCount = allVulns.Count(v => v.Severity == "High"),
            MediumCount = allVulns.Count(v => v.Severity == "Medium"),
            LowCount = allVulns.Count(v => v.Severity == "Low"),
            LastScanAt = _history.FirstOrDefault()?.ScanEndTime,
            LastScanTarget = _history.FirstOrDefault()?.TargetUrl
        };
    }

    /// <summary>Starts a new scan asynchronously.</summary>
    public Task<ScanJob> StartScanAsync(string targetUrl, string scanType, string profile)
    {
        var job = new ScanJob
        {
            JobId = Guid.NewGuid().ToString("N")[..12],
            TargetUrl = targetUrl,
            ScanType = scanType,
            Profile = profile,
            Status = ScanStatus.Running,
            StartedAt = DateTime.UtcNow
        };

        _scans[job.JobId] = job;

        // Run scan in background
        _ = Task.Run(async () =>
        {
            try
            {
                _config.ActiveProfile = profile;
                var report = new SecurityReport
                {
                    ScanProfile = profile,
                    TargetUrls = new List<string> { targetUrl },
                    ScanStartTime = DateTime.UtcNow
                };

                var modules = GetModulesForScanType(scanType);

                for (int i = 0; i < modules.Count; i++)
                {
                    var moduleName = modules[i];
                    job.CurrentModule = moduleName;
                    job.ProgressPercent = (int)((double)i / modules.Count * 100);

                    await RunModuleAsync(moduleName, targetUrl, report, job);

                    job.CompletedModules.Add(moduleName);
                }

                job.ProgressPercent = 100;
                job.CurrentModule = "";

                report.ScanEndTime = DateTime.UtcNow;
                await ReportGenerator.GenerateAsync(report, _config.OutputDirectory, _config.OutputFormat);

                job.ReportPath = Path.Combine(_config.OutputDirectory,
                    $"SecKit-Report-{report.GeneratedAt:yyyyMMdd-HHmmss}.html");
                job.TotalFindings = report.TotalVulnerabilities;
                job.AllVulnerabilities = report.AllVulnerabilities;
                job.ModuleResults = report.ModuleResults;
                job.Status = ScanStatus.Completed;
                job.CompletedAt = DateTime.UtcNow;

                // Add to history
                _history.Insert(0, new ScanHistoryItem
                {
                    JobId = job.JobId,
                    TargetUrl = targetUrl,
                    ScanType = scanType,
                    Profile = profile,
                    ScanStartTime = job.StartedAt,
                    ScanEndTime = job.CompletedAt!.Value,
                    TotalFindings = job.TotalFindings,
                    AllVulnerabilities = report.AllVulnerabilities,
                    ModuleResults = report.ModuleResults,
                    ReportPath = job.ReportPath,
                    CriticalCount = report.CriticalCount,
                    HighCount = report.HighCount,
                    MediumCount = report.MediumCount,
                    LowCount = report.LowCount,
                    InfoCount = report.InfoCount
                });

                // Keep only last 50
                while (_history.Count > 50)
                    _history.RemoveAt(_history.Count - 1);
            }
            catch (Exception ex)
            {
                job.Status = ScanStatus.Failed;
                job.ErrorMessage = ex.Message;
                Logger.Error($"Scan {job.JobId} failed: {ex}");
            }
        });

        return Task.FromResult(job);
    }

    private async Task RunModuleAsync(string moduleName, string targetUrl, SecurityReport report, ScanJob job)
    {
        job.ModuleStatuses[moduleName] = "running";
        job.StatusChanged();

        try
        {
            ScanResult result;

            switch (moduleName)
            {
                case "SQL Injection":
                    result = await new SqlInjectionTester(
                        HttpClientFactory.Create(_config), _config).TestAsync(targetUrl);
                    break;
                case "XSS":
                    result = await new XssTester(
                        HttpClientFactory.Create(_config), _config).TestAsync(targetUrl);
                    break;
                case "CSRF":
                    result = await new CsrfTester(
                        HttpClientFactory.Create(_config), _config).TestAsync(targetUrl);
                    break;
                case "SSRF":
                    result = await new SsrfTester(
                        HttpClientFactory.Create(_config), _config).TestAsync(targetUrl);
                    break;
                case "Path Traversal":
                    result = await new PathTraversalTester(
                        HttpClientFactory.Create(_config), _config).TestAsync(targetUrl);
                    break;
                case "Auth":
                    result = await new AuthTester(
                        HttpClientFactory.Create(_config), _config).TestAsync(targetUrl);
                    break;
                case "File Upload":
                    result = await new FileUploadTester(
                        HttpClientFactory.Create(_config), _config).TestAsync(targetUrl);
                    break;
                case "Port Scan":
                    result = await new PortScanner(_config).ScanAsync(targetUrl);
                    break;
                case "SSL/TLS":
                    if (targetUrl.StartsWith("https://"))
                        result = await new SslChecker(_config).CheckAsync(targetUrl);
                    else
                        result = new ScanResult { ModuleName = "SSL/TLS", Completed = true,
                            ErrorMessage = "Skipped — not HTTPS" };
                    break;
                case "Headers":
                    result = await new HeaderAnalyzer(
                        HttpClientFactory.Create(_config), _config).AnalyzeAsync(targetUrl);
                    break;
                case "Prompt Injection":
                    result = await new PromptInjectionTester(
                        HttpClientFactory.Create(_config), _config).TestAsync(targetUrl);
                    break;
                case "Function Abuse":
                    result = await new FunctionCallAbuseTester(
                        HttpClientFactory.Create(_config), _config).TestAsync(targetUrl);
                    break;
                case "Data Leakage":
                    result = await new DataLeakageTester(
                        HttpClientFactory.Create(_config), _config).TestAsync(targetUrl);
                    break;
                case "Crawler":
                    result = await new Crawler(
                        HttpClientFactory.Create(_config), _config).CrawlAsync(targetUrl);
                    break;
                case "Fuzzer":
                    result = await new Fuzzer(
                        HttpClientFactory.Create(_config), _config).FuzzAsync(targetUrl);
                    break;
                default:
                    result = new ScanResult { ModuleName = moduleName, Completed = true,
                        ErrorMessage = $"Unknown module: {moduleName}" };
                    break;
            }

            report.ModuleResults.Add(result);
            report.AllVulnerabilities.AddRange(result.Vulnerabilities);

            job.ModuleStatuses[moduleName] = result.Completed ? "completed" : "failed";
            if (!string.IsNullOrEmpty(result.ErrorMessage))
                job.ModuleErrors[moduleName] = result.ErrorMessage;
        }
        catch (Exception ex)
        {
            job.ModuleStatuses[moduleName] = "failed";
            job.ModuleErrors[moduleName] = ex.Message;
        }

        job.StatusChanged();
    }

    private List<string> GetModulesForScanType(string scanType) => scanType.ToLower() switch
    {
        "full" => new()
        {
            "SQL Injection", "XSS", "CSRF", "SSRF", "Path Traversal", "Auth", "File Upload",
            "Port Scan", "SSL/TLS", "Headers",
            "Prompt Injection", "Function Abuse", "Data Leakage",
            "Crawler", "Fuzzer"
        },
        "vuln" => new() { "SQL Injection", "XSS", "CSRF", "SSRF", "Path Traversal", "Auth", "File Upload" },
        "network" => new() { "Port Scan", "SSL/TLS", "Headers" },
        "ai" => new() { "Prompt Injection", "Function Abuse", "Data Leakage" },
        "map" => new() { "Crawler", "Fuzzer" },
        "vuln-sqli" => new() { "SQL Injection" },
        "vuln-xss" => new() { "XSS" },
        "vuln-csrf" => new() { "CSRF" },
        "vuln-ssrf" => new() { "SSRF" },
        "vuln-path" => new() { "Path Traversal" },
        "vuln-auth" => new() { "Auth" },
        "vuln-upload" => new() { "File Upload" },
        "net-port" => new() { "Port Scan" },
        "net-ssl" => new() { "SSL/TLS" },
        "net-headers" => new() { "Headers" },
        _ => new() { "SQL Injection", "XSS", "CSRF", "SSRF", "Path Traversal", "Auth", "File Upload" }
    };

    private void LoadHistoryFromDisk()
    {
        try
        {
            var reportsDir = _config.OutputDirectory;
            if (!Directory.Exists(reportsDir)) return;

            var jsonFiles = Directory.GetFiles(reportsDir, "*.json")
                .OrderByDescending(f => f)
                .Take(50);

            foreach (var jsonFile in jsonFiles)
            {
                try
                {
                    var json = File.ReadAllText(jsonFile);
                    var report = JsonSerializer.Deserialize<SecurityReport>(json,
                        new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

                    if (report == null) continue;

                    var htmlFile = Path.ChangeExtension(jsonFile, ".html");
                    _history.Add(new ScanHistoryItem
                    {
                        JobId = report.ReportId,
                        TargetUrl = report.TargetUrls.FirstOrDefault() ?? "unknown",
                        ScanType = "unknown",
                        Profile = report.ScanProfile,
                        ScanStartTime = report.ScanStartTime,
                        ScanEndTime = report.ScanEndTime,
                        TotalFindings = report.TotalVulnerabilities,
                        AllVulnerabilities = report.AllVulnerabilities,
                        ModuleResults = report.ModuleResults,
                        ReportPath = File.Exists(htmlFile) ? htmlFile : jsonFile,
                        CriticalCount = report.CriticalCount,
                        HighCount = report.HighCount,
                        MediumCount = report.MediumCount,
                        LowCount = report.LowCount,
                        InfoCount = report.InfoCount
                    });
                }
                catch { /* skip corrupted reports */ }
            }
        }
        catch { /* history loading is best-effort */ }
    }
}

/// <summary>A single scan job with live progress tracking.</summary>
public class ScanJob
{
    public string JobId { get; set; } = "";
    public string TargetUrl { get; set; } = "";
    public string ScanType { get; set; } = "full";
    public string Profile { get; set; } = "medium";
    public ScanStatus Status { get; set; } = ScanStatus.Pending;
    public int ProgressPercent { get; set; }
    public string CurrentModule { get; set; } = "";
    public DateTime StartedAt { get; set; }
    public DateTime? CompletedAt { get; set; }
    public int TotalFindings { get; set; }
    public string? ReportPath { get; set; }
    public string? ErrorMessage { get; set; }
    public List<string> CompletedModules { get; set; } = new();
    public Dictionary<string, string> ModuleStatuses { get; set; } = new();
    public Dictionary<string, string> ModuleErrors { get; set; } = new();
    public List<Vulnerability> AllVulnerabilities { get; set; } = new();
    public List<ScanResult> ModuleResults { get; set; } = new();

    public TimeSpan Duration =>
        (CompletedAt ?? DateTime.UtcNow) - StartedAt;

    // Event for Blazor to re-render on status change
    public event Action? OnStatusChanged;

    public void StatusChanged() => OnStatusChanged?.Invoke();
}

/// <summary>Dashboard quick statistics.</summary>
public class DashboardStats
{
    public int TotalScans { get; set; }
    public int TotalVulnerabilities { get; set; }
    public int CriticalCount { get; set; }
    public int HighCount { get; set; }
    public int MediumCount { get; set; }
    public int LowCount { get; set; }
    public DateTime? LastScanAt { get; set; }
    public string? LastScanTarget { get; set; }
}

/// <summary>Historical scan item for the dashboard and results page.</summary>
public class ScanHistoryItem
{
    public string JobId { get; set; } = "";
    public string TargetUrl { get; set; } = "";
    public string ScanType { get; set; } = "";
    public string Profile { get; set; } = "";
    public DateTime ScanStartTime { get; set; }
    public DateTime ScanEndTime { get; set; }
    public int TotalFindings { get; set; }
    public int CriticalCount { get; set; }
    public int HighCount { get; set; }
    public int MediumCount { get; set; }
    public int LowCount { get; set; }
    public int InfoCount { get; set; }
    public List<Vulnerability> AllVulnerabilities { get; set; } = new();
    public List<ScanResult> ModuleResults { get; set; } = new();
    public string? ReportPath { get; set; }
    public TimeSpan Duration => ScanEndTime - ScanStartTime;
}

public enum ScanStatus
{
    Pending,
    Running,
    Completed,
    Failed
}
