using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using SecKit.Core;
using SecKit.Models;
using SecKit.Modules.NetworkScanner;

namespace SecKit.Agent;

/// <summary>Background worker that runs periodic security scans and sends alerts.</summary>
public class Worker : BackgroundService
{
    private readonly AgentConfig _config;
    private readonly ConfigManager _secKitConfig;
    private readonly ILogger<Worker> _logger;
    private readonly HttpClient _httpClient;
    private HashSet<int> _lastOpenPorts = new();
    private DateTime _lastLogCheck = DateTime.MinValue;

    public Worker(
        IOptions<AgentConfig> options,
        ConfigManager secKitConfig,
        ILogger<Worker> logger)
    {
        _config = options.Value;
        _secKitConfig = secKitConfig;
        _logger = logger;
        _httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Ensure log directory
        var logDir = Path.GetDirectoryName(_config.LogPath);
        if (!string.IsNullOrEmpty(logDir))
            Directory.CreateDirectory(logDir);

        await LogToFileAsync("SecKit Agent started.");
        _logger.LogInformation("SecKit Agent started. Interval: {Interval}", _config.Interval);

        // Run immediate initial scan
        await RunScanCycleAsync(stoppingToken);

        // Periodic loop
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(_config.Interval, stoppingToken);
                await RunScanCycleAsync(stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                await LogToFileAsync($"Error in scan cycle: {ex.Message}");
                _logger.LogError(ex, "Error in scan cycle");
                await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken);
            }
        }

        await LogToFileAsync("SecKit Agent stopped.");
    }

    private async Task RunScanCycleAsync(CancellationToken ct)
    {
        var timestamp = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss");
        await LogToFileAsync($"[{timestamp}] Starting scan cycle.");

        var targets = _config.MonitoredTargets;
        if (targets.Count == 0)
            targets = _secKitConfig.TargetUrls;

        if (targets.Count == 0)
        {
            await LogToFileAsync("No targets configured. Skipping scan cycle.");
            return;
        }

        _secKitConfig.ActiveProfile = _config.ScanProfile;

        foreach (var target in targets)
        {
            if (ct.IsCancellationRequested) break;

            try
            {
                await LogToFileAsync($"Scanning: {target} (type: {_config.ScanType})");

                var report = new SecurityReport
                {
                    ScanProfile = _config.ScanProfile,
                    TargetUrls = new List<string> { target },
                    ScanStartTime = DateTime.UtcNow
                };

                // Run appropriate scan modules based on type
                await RunScanModulesAsync(target, report, ct);

                report.ScanEndTime = DateTime.UtcNow;

                // Generate report
                await ReportGenerator.GenerateAsync(report,
                    _secKitConfig.OutputDirectory, _secKitConfig.OutputFormat);

                // Check for alerts
                await SendAlertsIfNeededAsync(report, target);

                await LogToFileAsync(
                    $"Scan complete: {target} — {report.TotalVulnerabilities} findings " +
                    $"(C:{report.CriticalCount} H:{report.HighCount} M:{report.MediumCount} L:{report.LowCount})");
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                await LogToFileAsync($"Error scanning {target}: {ex.Message}");
                _logger.LogError(ex, "Error scanning {Target}", target);
            }
        }

        // Monitor for new open ports if enabled
        if (_config.MonitorOpenPorts)
        {
            await CheckNewOpenPortsAsync(ct);
        }

        // Monitor log files if enabled
        if (_config.MonitorLogs)
        {
            await CheckLogFilesAsync(ct);
        }

        await LogToFileAsync($"[{timestamp}] Scan cycle complete.");
    }

    private async Task RunScanModulesAsync(string target, SecurityReport report, CancellationToken ct)
    {
        var scanType = _config.ScanType.ToLower();

        if (scanType is "full" or "vuln")
        {
            var httpClient = HttpClientFactory.Create(_secKitConfig);

            var vulnTesters = new Dictionary<string, Func<Task<ScanResult>>>
            {
                ["SQL Injection"] = async () => await new Modules.VulnerabilityScanner.SqlInjectionTester(httpClient, _secKitConfig).TestAsync(target),
                ["XSS"] = async () => await new Modules.VulnerabilityScanner.XssTester(httpClient, _secKitConfig).TestAsync(target),
                ["CSRF"] = async () => await new Modules.VulnerabilityScanner.CsrfTester(httpClient, _secKitConfig).TestAsync(target),
                ["SSRF"] = async () => await new Modules.VulnerabilityScanner.SsrfTester(httpClient, _secKitConfig).TestAsync(target),
                ["Path Traversal"] = async () => await new Modules.VulnerabilityScanner.PathTraversalTester(httpClient, _secKitConfig).TestAsync(target),
                ["Auth"] = async () => await new Modules.VulnerabilityScanner.AuthTester(httpClient, _secKitConfig).TestAsync(target),
                ["File Upload"] = async () => await new Modules.VulnerabilityScanner.FileUploadTester(httpClient, _secKitConfig).TestAsync(target),
            };

            foreach (var (name, testFunc) in vulnTesters)
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    var result = await testFunc();
                    report.ModuleResults.Add(result);
                    report.AllVulnerabilities.AddRange(result.Vulnerabilities);
                }
                catch (Exception ex)
                {
                    report.ModuleResults.Add(new ScanResult
                    {
                        ModuleName = name,
                        TargetUrl = target,
                        Completed = false,
                        ErrorMessage = ex.Message
                    });
                }
            }
        }

        if (scanType is "full" or "network")
        {
            try
            {
                var portScanner = new PortScanner(_secKitConfig);
                var portResult = await portScanner.ScanAsync(target);
                report.ModuleResults.Add(portResult);
                report.AllVulnerabilities.AddRange(portResult.Vulnerabilities);
            }
            catch { }

            try
            {
                var headerAnalyzer = new HeaderAnalyzer(
                    HttpClientFactory.Create(_secKitConfig), _secKitConfig);
                var headerResult = await headerAnalyzer.AnalyzeAsync(target);
                report.ModuleResults.Add(headerResult);
                report.AllVulnerabilities.AddRange(headerResult.Vulnerabilities);
            }
            catch { }

            if (target.StartsWith("https://"))
            {
                try
                {
                    var sslChecker = new SslChecker(_secKitConfig);
                    var sslResult = await sslChecker.CheckAsync(target);
                    report.ModuleResults.Add(sslResult);
                    report.AllVulnerabilities.AddRange(sslResult.Vulnerabilities);
                }
                catch { }
            }
        }

        if (scanType is "full" or "ai")
        {
            try
            {
                var piTester = new Modules.AiSecurityTester.PromptInjectionTester(
                    HttpClientFactory.Create(_secKitConfig), _secKitConfig);
                var piResult = await piTester.TestAsync(target);
                report.ModuleResults.Add(piResult);
                report.AllVulnerabilities.AddRange(piResult.Vulnerabilities);
            }
            catch { }

            try
            {
                var fcTester = new Modules.AiSecurityTester.FunctionCallAbuseTester(
                    HttpClientFactory.Create(_secKitConfig), _secKitConfig);
                var fcResult = await fcTester.TestAsync(target);
                report.ModuleResults.Add(fcResult);
                report.AllVulnerabilities.AddRange(fcResult.Vulnerabilities);
            }
            catch { }

            try
            {
                var dlTester = new Modules.AiSecurityTester.DataLeakageTester(
                    HttpClientFactory.Create(_secKitConfig), _secKitConfig);
                var dlResult = await dlTester.TestAsync(target);
                report.ModuleResults.Add(dlResult);
                report.AllVulnerabilities.AddRange(dlResult.Vulnerabilities);
            }
            catch { }
        }

        if (scanType is "full" or "map")
        {
            try
            {
                var crawler = new Modules.SiteMapper.Crawler(
                    HttpClientFactory.Create(_secKitConfig), _secKitConfig);
                var crawlResult = await crawler.CrawlAsync(target);
                report.ModuleResults.Add(crawlResult);
                report.AllVulnerabilities.AddRange(crawlResult.Vulnerabilities);
            }
            catch { }

            try
            {
                var fuzzer = new Modules.SiteMapper.Fuzzer(
                    HttpClientFactory.Create(_secKitConfig), _secKitConfig);
                var fuzzResult = await fuzzer.FuzzAsync(target);
                report.ModuleResults.Add(fuzzResult);
                report.AllVulnerabilities.AddRange(fuzzResult.Vulnerabilities);
            }
            catch { }
        }
    }

    private async Task SendAlertsIfNeededAsync(SecurityReport report, string target)
    {
        var thresholdOrder = new Dictionary<string, int>
        {
            ["Info"] = 0, ["Low"] = 1, ["Medium"] = 2, ["High"] = 3, ["Critical"] = 4
        };

        var threshold = thresholdOrder.GetValueOrDefault(_config.AlertThreshold, 3);
        var hasAlertableVulns = report.AllVulnerabilities.Any(v =>
            thresholdOrder.GetValueOrDefault(v.Severity, 0) >= threshold);

        if (!hasAlertableVulns) return;

        var criticalList = report.AllVulnerabilities
            .Where(v => thresholdOrder.GetValueOrDefault(v.Severity, 0) >= threshold)
            .OrderByDescending(v => thresholdOrder.GetValueOrDefault(v.Severity, 0))
            .Take(5).ToList();

        var message = new StringBuilder();
        message.AppendLine($"\ud83d\udea8 *SecKit Alert* — {target}");
        message.AppendLine($"Found {report.TotalVulnerabilities} vulns ({report.CriticalCount} critical, {report.HighCount} high)");
        message.AppendLine();

        foreach (var v in criticalList)
            message.AppendLine($"  \u2022 [{v.Severity}] {v.Type}: {v.Description}");

        if (criticalList.Count < report.AllVulnerabilities.Count(v =>
            thresholdOrder.GetValueOrDefault(v.Severity, 0) >= threshold))
            message.AppendLine($"  ... and {report.AllVulnerabilities.Count(v => thresholdOrder.GetValueOrDefault(v.Severity, 0) >= threshold) - criticalList.Count} more");

        // Send Telegram alert
        if (!string.IsNullOrEmpty(_config.TelegramBotToken) &&
            !string.IsNullOrEmpty(_config.TelegramChatId))
        {
            await SendTelegramAlertAsync(message.ToString());
        }

        // Send webhook alert
        if (_config.WebhookEnabled && !string.IsNullOrEmpty(_config.WebhookUrl))
        {
            await SendWebhookAlertAsync(report, message.ToString());
        }
    }

    private async Task SendTelegramAlertAsync(string message)
    {
        try
        {
            var url = $"https://api.telegram.org/bot{_config.TelegramBotToken}/sendMessage";
            var payload = JsonSerializer.Serialize(new
            {
                chat_id = _config.TelegramChatId,
                text = message,
                parse_mode = "Markdown"
            });

            var content = new StringContent(payload, Encoding.UTF8, "application/json");
            var response = await _httpClient.PostAsync(url, content);

            if (!response.IsSuccessStatusCode)
                _logger.LogWarning("Telegram alert failed: {Status}", response.StatusCode);
            else
                await LogToFileAsync("Telegram alert sent.");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to send Telegram alert");
        }
    }

    private async Task SendWebhookAlertAsync(SecurityReport report, string message)
    {
        try
        {
            var payload = JsonSerializer.Serialize(new
            {
                timestamp = DateTime.UtcNow.ToString("o"),
                alert = "vulnerability_found",
                target = report.TargetUrls.FirstOrDefault(),
                critical = report.CriticalCount,
                high = report.HighCount,
                medium = report.MediumCount,
                low = report.LowCount,
                total = report.TotalVulnerabilities,
                message
            });

            var content = new StringContent(payload, Encoding.UTF8, "application/json");
            var response = await _httpClient.PostAsync(_config.WebhookUrl, content);

            if (!response.IsSuccessStatusCode)
                _logger.LogWarning("Webhook alert failed: {Status}", response.StatusCode);
            else
                await LogToFileAsync("Webhook alert sent.");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to send webhook alert");
        }
    }

    private async Task CheckNewOpenPortsAsync(CancellationToken ct)
    {
        try
        {
            var hostname = Environment.MachineName;
            var portScanner = new PortScanner(_secKitConfig);

            // Use localhost for port scan
            var result = await portScanner.ScanAsync("http://localhost");

            var currentPorts = new HashSet<int>();
            // Extract port numbers from scan results
            foreach (var vuln in result.Vulnerabilities)
            {
                // Port scanner results contain port numbers in URL or parameter
                if (int.TryParse(vuln.Parameter, out var port))
                    currentPorts.Add(port);
            }

            if (_lastOpenPorts.Count > 0)
            {
                var newPorts = currentPorts.Except(_lastOpenPorts).ToList();
                var closedPorts = _lastOpenPorts.Except(currentPorts).ToList();

                if (newPorts.Any())
                {
                    var alert = $"\ud83d\udd11 *New Open Ports Detected*\n" +
                               $"Host: {hostname}\n" +
                               $"New ports: {string.Join(", ", newPorts)}";
                    await SendTelegramAlertAsync(alert);
                    await LogToFileAsync($"New open ports: {string.Join(", ", newPorts)}");
                }

                if (closedPorts.Any())
                    await LogToFileAsync($"Ports closed: {string.Join(", ", closedPorts)}");
            }

            _lastOpenPorts = currentPorts;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Port monitoring error");
        }
    }

    private async Task CheckLogFilesAsync(CancellationToken ct)
    {
        foreach (var logPath in _config.LogFilesToMonitor)
        {
            try
            {
                if (!File.Exists(logPath)) continue;

                var lastWrite = File.GetLastWriteTimeUtc(logPath);
                if (lastWrite <= _lastLogCheck) continue;

                // Quick check for suspicious patterns
                var suspiciousPatterns = new[]
                {
                    "union select", "or 1=1", "' OR '1'='1",
                    "<script>", "javascript:", "onerror=", "onload=",
                    "../../../etc/passwd", "cmd.exe", "/bin/bash",
                    "wget ", "curl ", "nc -e"
                };

                // Read last 1000 lines
                var lines = await File.ReadAllLinesAsync(logPath, ct);
                var recentLines = lines.Skip(Math.Max(0, lines.Length - 1000));
                var hits = new List<string>();

                foreach (var line in recentLines)
                {
                    foreach (var pattern in suspiciousPatterns)
                    {
                        if (line.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        {
                            hits.Add(line.Length > 200 ? line[..200] + "..." : line);
                            break;
                        }
                    }
                }

                if (hits.Any())
                {
                    var uniqueHits = hits.Distinct().Take(10).ToList();
                    var alert = $"\ud83d\uded1 *Suspicious Log Activity*\n" +
                               $"File: {logPath}\n" +
                               $"Patterns matched: {uniqueHits.Count}\n\n" +
                               string.Join("\n", uniqueHits.Select(h => $"\u2022 `{Truncate(h, 100)}`"));

                    await SendTelegramAlertAsync(alert);
                    await LogToFileAsync($"Suspicious log activity in {logPath}: {hits.Count} hits");
                }

                _lastLogCheck = lastWrite;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Log monitoring error for {Path}", logPath);
            }
        }
    }

    private static string Truncate(string value, int maxLength) =>
        value.Length <= maxLength ? value : value[..maxLength] + "...";

    private async Task LogToFileAsync(string message)
    {
        try
        {
            var logDir = Path.GetDirectoryName(_config.LogPath);
            if (!string.IsNullOrEmpty(logDir) && !Directory.Exists(logDir))
                Directory.CreateDirectory(logDir);

            var line = $"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}] {message}{Environment.NewLine}";
            await File.AppendAllTextAsync(_config.LogPath, line);
        }
        catch { /* logging failure is non-critical */ }
    }
}
