using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using SecKit.Core;
using SecKit.Models;

namespace SecKit.Modules.Crypto;

/// <summary>
/// VirusTotal API v3 scanner for file hash lookups. Rate limits driven by appsettings.json.
/// </summary>
public class VirusTotalScanner
{
    private readonly HttpClient _client;
    private readonly ConfigManager _config;
    private readonly string _apiKey;
    private readonly string _cacheFilePath;

    private readonly TimeSpan _rateWindow = TimeSpan.FromMinutes(1);
    private readonly int _rateLimit;
    private readonly TimeSpan _minInterval;

    private DateTime _lastRequest = DateTime.MinValue;
    private int _requestsThisWindow;
    private DateTime _windowStart = DateTime.MinValue;

    private readonly ConcurrentDictionary<string, VtCacheEntry> _cache = new();

    public VirusTotalScanner(HttpClient client, ConfigManager config)
    {
        _client = client;
        _config = config;
        _apiKey = config.GetCustomValue("virustotal:apiKey")
                  ?? Environment.GetEnvironmentVariable("VT_API_KEY") ?? "";
        _cacheFilePath = Path.Combine(config.OutputDirectory, "vt_cache.json");

        var rpm = config.VirusTotalRequestsPerMinute;
        _rateLimit = Math.Max(1, rpm);
        _minInterval = TimeSpan.FromSeconds(60.0 / Math.Max(1, rpm));
        LoadCache();
    }

    public async Task<ScanResult> ScanAsync(string target)
    {
        var result = new ScanResult { ModuleName = "VirusTotal Scanner", TargetUrl = target, StartTime = DateTime.UtcNow };

        if (string.IsNullOrWhiteSpace(_apiKey))
        {
            AddVuln(result, target, "", "VT: Missing API Key", "Set 'virustotal:apiKey' in config or VT_API_KEY env var.", "Info", 10, "Get a free key from https://www.virustotal.com/gui/join-us");
            result.Completed = true; result.EndTime = DateTime.UtcNow;
            return result;
        }

        try
        {
            if (Regex.IsMatch(target, @"^[a-fA-F0-9]{64}$"))
            { result.EndpointsTested = 1; await CheckHashAsync(result, target, target); }
            else if (Directory.Exists(target))
            { await ScanDirectoryAsync(result, target); }
            else if (File.Exists(target))
            { await ScanFileAsync(result, target); }
            else
            { AddVuln(result, target, "", "VT: Invalid Target", "Not a valid SHA-256 hash, file, or directory.", "Info", 10, null); }
            result.Completed = true;
        }
        catch (Exception ex) { result.ErrorMessage = ex.Message; Logger.Error($"VirusTotal Scanner failed: {ex.Message}"); }

        result.EndTime = DateTime.UtcNow;
        SaveCache();
        return result;
    }

    private async Task ScanDirectoryAsync(ScanResult result, string directory)
    {
        var files = Directory.GetFiles(directory, "*", SearchOption.AllDirectories).Take(500).ToList();
        result.EndpointsTested = files.Count;
        foreach (var file in files)
        {
            try { var fi = new FileInfo(file); if (fi.Length > 100 * 1024 * 1024) continue; var hash = await ComputeSha256FileHashAsync(file); result.RequestsSent++; await CheckHashAsync(result, file, hash); }
            catch (Exception ex) { Logger.Debug($"VT: could not process {file}: {ex.Message}"); }
        }
    }

    private async Task ScanFileAsync(ScanResult result, string filePath)
    {
        result.EndpointsTested = 1;
        var hash = await ComputeSha256FileHashAsync(filePath); result.RequestsSent++;
        await CheckHashAsync(result, filePath, hash);
    }

    private async Task CheckHashAsync(ScanResult result, string source, string hash)
    {
        if (_cache.TryGetValue(hash, out var cached) && (DateTime.UtcNow - cached.Timestamp) < TimeSpan.FromHours(24))
        { ProcessResponse(result, source, hash, cached.Data); return; }

        await RespectRateLimitAsync();
        try
        {
            var request = new HttpRequestMessage(HttpMethod.Get, $"https://www.virustotal.com/api/v3/files/{hash}");
            request.Headers.Add("x-apikey", _apiKey);
            _lastRequest = DateTime.UtcNow; TrackRateLimit();
            var response = await _client.SendAsync(request); result.RequestsSent++;

            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            { _cache[hash] = new VtCacheEntry { Timestamp = DateTime.UtcNow, Data = new VtData { Id = hash, NotFound = true } }; }
            else if (response.StatusCode == System.Net.HttpStatusCode.TooManyRequests)
            { Logger.Warning("VT rate limit hit — cooling down 60s."); await Task.Delay(60000); response = await _client.SendAsync(request); result.RequestsSent++; }

            if (response.IsSuccessStatusCode)
            {
                var json = await response.Content.ReadAsStringAsync();
                var apiResp = JsonSerializer.Deserialize<VtApiResponse>(json);
                if (apiResp?.Data != null) { _cache[hash] = new VtCacheEntry { Timestamp = DateTime.UtcNow, Data = apiResp.Data }; ProcessResponse(result, source, hash, apiResp.Data); }
            }
        }
        catch (TaskCanceledException) { Logger.Debug($"VT timeout: {hash}"); }
        catch (Exception ex) { Logger.Debug($"VT error: {ex.Message}"); }
    }

    private void ProcessResponse(ScanResult result, string source, string hash, VtData data)
    {
        if (data.NotFound) return;
        var stats = data.Attributes?.LastAnalysisStats; if (stats == null) return;
        var total = stats.Malicious + stats.Suspicious + stats.Harmless + stats.Undetected + stats.Timeout;
        var ratio = total > 0 ? (double)(stats.Malicious + stats.Suspicious) / total * 100 : 0;
        var fileType = data.Attributes?.TypeDescription ?? data.Attributes?.Magic ?? "unknown";
        var engines = data.Attributes?.LastAnalysisResults?.Where(r => r.Value?.Category is "malicious" or "suspicious").Select(r => r.Key).Take(10).ToList() ?? new List<string>();

        if (stats.Malicious >= 5)
            AddVuln(result, source, hash, "VirusTotal: Malware Detected", $"Flagged by {stats.Malicious} engines ({ratio:F0}% detection). Type: {fileType}. Engines: {string.Join(", ", engines)}", "Critical", 95, $"SHA-256: {hash}\nMalicious: {stats.Malicious}, Suspicious: {stats.Suspicious}, Engines: {string.Join(", ", engines)}");
        else if (stats.Malicious >= 2 || stats.Suspicious >= 3)
            AddVuln(result, source, hash, "VirusTotal: Suspicious File", $"{stats.Malicious} malicious, {stats.Suspicious} suspicious ({ratio:F0}%). Type: {fileType}.", "High", 70, $"SHA-256: {hash}");
        else
            Logger.Debug($"VT: {Path.GetFileName(source)} — {stats.Malicious} malicious, clean otherwise ({ratio:F0}%)");
    }

    private async Task RespectRateLimitAsync()
    {
        var now = DateTime.UtcNow;
        if (now - _windowStart > _rateWindow) { _windowStart = now; _requestsThisWindow = 0; }
        if (_requestsThisWindow >= _rateLimit)
        {
            var wait = (_windowStart + _rateWindow) - now;
            if (wait > TimeSpan.Zero) { Logger.Debug($"VT rate limit — waiting {wait.TotalSeconds:F0}s"); await Task.Delay(wait); _windowStart = DateTime.UtcNow; _requestsThisWindow = 0; }
        }
        var sinceLast = now - _lastRequest;
        if (sinceLast < _minInterval) await Task.Delay(_minInterval - sinceLast);
    }

    private void TrackRateLimit()
    {
        var now = DateTime.UtcNow;
        if (now - _windowStart > _rateWindow) { _windowStart = now; _requestsThisWindow = 0; }
        _requestsThisWindow++;
    }

    private static async Task<string> ComputeSha256FileHashAsync(string filePath)
    { using var stream = File.OpenRead(filePath); var hash = await SHA256.HashDataAsync(stream); return Convert.ToHexString(hash).ToLowerInvariant(); }

    private void LoadCache()
    {
        try { if (File.Exists(_cacheFilePath)) { var json = File.ReadAllText(_cacheFilePath); var entries = JsonSerializer.Deserialize<Dictionary<string, VtCacheEntry>>(json); if (entries != null) foreach (var (k, v) in entries) _cache[k] = v; Logger.Debug($"Loaded {_cache.Count} cached VT results"); } } catch { }
    }

    private void SaveCache()
    {
        try { var json = JsonSerializer.Serialize(_cache.ToDictionary(kv => kv.Key, kv => kv.Value), new JsonSerializerOptions { WriteIndented = true }); File.WriteAllText(_cacheFilePath, json); } catch { }
    }

    private void AddVuln(ScanResult result, string source, string hash, string type, string desc, string severity, int confidence, string? evidence = null)
    {
        var v = new Vulnerability { Type = type, Severity = severity, Url = source, Parameter = "VirusTotal", Payload = hash, Description = desc, Evidence = evidence ?? $"SHA-256: {hash}", Remediation = type.Contains("Malware") || type.Contains("Suspicious") ? "Isolate and investigate this file immediately." : "Check VirusTotal documentation for API key setup.", Module = "VirusTotalScanner", Confidence = confidence };
        result.Vulnerabilities.Add(v); Logger.LogVulnerability(v);
    }
}

// ─── JSON Models ───
public class VtApiResponse { [JsonPropertyName("data")] public VtData? Data { get; set; } }
public class VtData { [JsonPropertyName("id")] public string Id { get; set; } = ""; [JsonPropertyName("type")] public string Type { get; set; } = "file"; [JsonPropertyName("attributes")] public VtAttrs? Attributes { get; set; } [JsonIgnore] public bool NotFound { get; set; } }
public class VtAttrs { [JsonPropertyName("type_description")] public string? TypeDescription { get; set; } [JsonPropertyName("magic")] public string? Magic { get; set; } [JsonPropertyName("last_analysis_stats")] public VtStats? LastAnalysisStats { get; set; } [JsonPropertyName("last_analysis_results")] public Dictionary<string, VtEngine>? LastAnalysisResults { get; set; } }
public class VtStats { [JsonPropertyName("malicious")] public int Malicious { get; set; } [JsonPropertyName("suspicious")] public int Suspicious { get; set; } [JsonPropertyName("harmless")] public int Harmless { get; set; } [JsonPropertyName("undetected")] public int Undetected { get; set; } [JsonPropertyName("timeout")] public int Timeout { get; set; } }
public class VtEngine { [JsonPropertyName("category")] public string? Category { get; set; } [JsonPropertyName("result")] public string? Result { get; set; } }
public class VtCacheEntry { [JsonPropertyName("timestamp")] public DateTime Timestamp { get; set; } [JsonPropertyName("data")] public VtData Data { get; set; } = new(); }
