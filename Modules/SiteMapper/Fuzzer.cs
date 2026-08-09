using System.Collections.Concurrent;
using SecKit.Core;
using SecKit.Models;

namespace SecKit.Modules.SiteMapper;

/// <summary>Fuzzes discovered endpoints with wordlists to find hidden paths and files.</summary>
public class Fuzzer
{
    private readonly HttpClient _client;
    private readonly ConfigManager _config;
    private readonly int _threads;
    private readonly string[] _commonPaths;
    private readonly string[] _commonParams;

    public Fuzzer(HttpClient client, ConfigManager config)
    {
        _client = client;
        _config = config;
        _threads = config.Threads;
        _commonPaths = config.FuzzPaths.ToArray();
        _commonParams = config.FuzzParameterNames.ToArray();
    }

    public async Task<ScanResult> FuzzAsync(string baseUrl)
    {
        var result = new ScanResult { ModuleName = "Directory/File Fuzzer", TargetUrl = baseUrl, StartTime = DateTime.UtcNow };
        try
        {
            var fuzzCount = Math.Min(_config.FuzzParams, _commonPaths.Length);
            var paths = _commonPaths.Take(fuzzCount);
            Logger.Info($"Fuzzing {baseUrl} with {fuzzCount} paths ({_threads} threads)...");

            var foundPaths = new ConcurrentBag<(string Path, int StatusCode, long ContentLength)>();
            using var semaphore = new SemaphoreSlim(_threads);
            var tasks = new List<Task>();

            foreach (var path in paths)
            {
                await semaphore.WaitAsync();
                var currentPath = path;
                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        var testUrl = CombineUrl(baseUrl, currentPath);
                        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                        var response = await _client.GetAsync(testUrl, cts.Token);
                        var statusCode = (int)response.StatusCode;
                        result.RequestsSent++;
                        if (statusCode is 200 or 301 or 302 or 403)
                        {
                            var contentLength = response.Content.Headers.ContentLength ?? 0;
                            foundPaths.Add((currentPath, statusCode, contentLength));
                            var color = statusCode switch { 200 => ConsoleColor.Green, 301 or 302 => ConsoleColor.Cyan, 403 => ConsoleColor.Yellow, _ => ConsoleColor.Gray };
                            Logger.WriteLine($"  [{statusCode}] /{currentPath}", color);
                        }
                    }
                    catch { }
                    finally { semaphore.Release(); }
                }));
                if (tasks.Count % 10 == 0) await Task.Delay(50);
            }
            await Task.WhenAll(tasks);
            result.EndpointsTested = fuzzCount;

            foreach (var (path, statusCode, contentLength) in foundPaths.OrderBy(p => p.StatusCode))
            {
                var severity = path switch { string p when p.Contains(".env") || p.Contains("backup") || p.Contains("config") => "High", string p when p.Contains(".git") || p.Contains("admin") || p.Contains("phpmyadmin") => "Medium", _ => "Low" };
                result.Vulnerabilities.Add(new Vulnerability { Type = "Discovered Resource", Severity = severity, Url = CombineUrl(baseUrl, path), Parameter = "path", Payload = path, Description = $"Found {path} (HTTP {statusCode}, {contentLength} bytes) — may expose sensitive info.", Remediation = statusCode == 403 ? "Verify directory listing is disabled and access controls are correct." : "Review if this resource should be publicly accessible. Restrict access as needed.", Module = "Fuzzer", Confidence = 100 });
            }

            Logger.Info($"Fuzzing complete: {foundPaths.Count} resources found.");
            result.Completed = true;
        }
        catch (Exception ex) { result.ErrorMessage = ex.Message; Logger.Error($"Fuzzer failed: {ex.Message}"); }
        result.EndTime = DateTime.UtcNow;
        return result;
    }

    public async Task<ScanResult> FuzzParametersAsync(string targetUrl, IEnumerable<string>? endpoints = null)
    {
        var result = new ScanResult { ModuleName = "Parameter Fuzzer", TargetUrl = targetUrl, StartTime = DateTime.UtcNow };
        try
        {
            var urls = new List<string> { targetUrl }; if (endpoints != null) urls.AddRange(endpoints);
            var foundParams = new ConcurrentBag<(string Url, string Param)>();
            using var semaphore = new SemaphoreSlim(_threads);
            var tasks = new List<Task>();

            foreach (var url in urls.Distinct())
            {
                foreach (var param in _commonParams.Take(Math.Min(_config.FuzzParams, 30)))
                {
                    await semaphore.WaitAsync();
                    var currentUrl = url; var currentParam = param;
                    tasks.Add(Task.Run(async () =>
                    {
                        try
                        {
                            var testUrl = AppendParam(currentUrl, currentParam, "FUZZ");
                            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                            var response = await _client.GetAsync(testUrl, cts.Token);
                            result.RequestsSent++; var body = await response.Content.ReadAsStringAsync(cts.Token);
                            if (body.Contains("FUZZ") || body.Contains("fuzz")) { foundParams.Add((currentUrl, currentParam)); Logger.WriteLine($"  ✓ Parameter '{currentParam}' reflected at {currentUrl}", ConsoleColor.Green); }
                        }
                        catch { }
                        finally { semaphore.Release(); }
                    }));
                }
            }
            await Task.WhenAll(tasks);

            foreach (var (url, param) in foundParams)
                result.Vulnerabilities.Add(new Vulnerability { Type = "Reflective Parameter", Severity = "Low", Url = url, Parameter = param, Description = $"Parameter '{param}' reflects user input — potential XSS/SSTI/Injection target.", Remediation = "Validate and encode all user input. Test this parameter for injection vulnerabilities.", Module = "Fuzzer", Confidence = 70 });

            result.EndpointsTested = urls.Count; result.Completed = true;
        }
        catch (Exception ex) { result.ErrorMessage = ex.Message; Logger.Error($"Parameter fuzzer failed: {ex.Message}"); }
        result.EndTime = DateTime.UtcNow;
        return result;
    }

    private static string CombineUrl(string baseUrl, string path) { var trimmed = baseUrl.TrimEnd('/'); return $"{trimmed}/{path.TrimStart('/')}"; }
    private static string AppendParam(string url, string key, string value) { var separator = url.Contains('?') ? "&" : "?"; return $"{url}{separator}{Uri.EscapeDataString(key)}={Uri.EscapeDataString(value)}"; }
}
