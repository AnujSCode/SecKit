using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using SecKit.Core;
using SecKit.Models;

namespace SecKit.Modules.TrafficAnalysis;

/// <summary>Parses IP addresses from logs and maps them to geographic locations.</summary>
public class GeoIpMapper
{
    private readonly HttpClient _client;
    private readonly ConfigManager _config;
    private readonly Dictionary<string, GeoInfo> _geoCache = new();

    /// <summary>Represents geographic information for an IP address.</summary>
    public record GeoInfo(string Ip, string Country, string CountryCode, string City, string Region,
        string Isp, double Latitude, double Longitude);

    public GeoIpMapper(HttpClient client, ConfigManager config)
    {
        _client = client;
        _config = config;
    }

    /// <summary>Analyzes a log file and maps IP addresses to geographic locations.</summary>
    public async Task<ScanResult> AnalyzeAsync(string logFilePath)
    {
        var result = new ScanResult
        {
            ModuleName = "GeoIP Mapper",
            TargetUrl = logFilePath,
            StartTime = DateTime.UtcNow
        };

        try
        {
            if (!File.Exists(logFilePath))
            {
                result.ErrorMessage = "Log file not found";
                result.Completed = true;
                result.EndTime = DateTime.UtcNow;
                return result;
            }

            Logger.Info($"Analyzing IPs from {logFilePath}...");

            // Extract IP addresses from log
            var ipPattern = @"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b";
            var lines = await File.ReadAllLinesAsync(logFilePath);
            result.EndpointsTested = lines.Length;

            var ipCounts = new Dictionary<string, int>();
            foreach (var line in lines)
            {
                result.RequestsSent++;
                var match = Regex.Match(line, ipPattern);
                if (match.Success)
                {
                    var ip = match.Groups[1].Value;
                    // Skip private IPs
                    if (!IsPrivateIp(ip))
                    {
                        ipCounts.TryGetValue(ip, out var count);
                        ipCounts[ip] = count + 1;
                    }
                }
            }

            var topIps = ipCounts.OrderByDescending(kv => kv.Value).Take(50).ToList();
            Logger.Info($"Found {ipCounts.Count} unique public IPs. Looking up top {topIps.Count}...");

            var geoInfos = new ConcurrentBag<GeoInfo>();
            using var semaphore = new SemaphoreSlim(5);

            var tasks = topIps.Select(async kvp =>
            {
                await semaphore.WaitAsync();
                try
                {
                    var geo = await LookupIpAsync(kvp.Key);
                    if (geo != null)
                    {
                        geoInfos.Add(geo);
                        Logger.WriteLine($"  {geo.Ip,-15} {geo.CountryCode,-4} {geo.City,-20} ({kvp.Value} requests)", ConsoleColor.Green);
                    }
                }
                catch (Exception ex)
                {
                    Logger.Debug($"GeoIP lookup failed for {kvp.Key}: {ex.Message}");
                }
                finally
                {
                    semaphore.Release();
                }
            });

            await Task.WhenAll(tasks);

            // Build traffic summary
            var byCountry = geoInfos.GroupBy(g => g.Country)
                .OrderByDescending(g => g.Count())
                .ToList();

            Logger.WriteLine($"\n🌍 Traffic Summary by Country:", ConsoleColor.Cyan);
            foreach (var country in byCountry)
            {
                var count = country.Count();
                var bar = new string('█', Math.Min(count, 30));
                Logger.WriteLine($"  {country.Key,-25} {bar} ({count})", ConsoleColor.White);
            }

            // Top cities
            var byCity = geoInfos.GroupBy(g => $"{g.City}, {g.CountryCode}")
                .OrderByDescending(g => g.Count())
                .Take(10);

            Logger.WriteLine($"\n🏙️  Top Cities:", ConsoleColor.Cyan);
            foreach (var city in byCity)
            {
                Logger.WriteLine($"  {city.Key,-30} ({city.Count()} IPs)", ConsoleColor.White);
            }

            // Add findings
            foreach (var country in byCountry.Take(5))
            {
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "Traffic Origin",
                    Severity = "Info",
                    Url = logFilePath,
                    Parameter = "IP",
                    Payload = country.Key,
                    Description = $"{country.Count()} unique IPs from {country.Key}",
                    Remediation = "Review geo-distribution. Consider geo-blocking if unusual patterns detected.",
                    Module = "GeoIpMapper",
                    Confidence = 100
                });
            }

            result.Completed = true;
        }
        catch (Exception ex)
        {
            result.ErrorMessage = ex.Message;
            Logger.Error($"GeoIP mapper failed: {ex.Message}");
        }

        result.EndTime = DateTime.UtcNow;
        return result;
    }

    /// <summary>Looks up a single IP address using a free geo-location service.</summary>
    public async Task<GeoInfo?> LookupIpAsync(string ip)
    {
        if (_geoCache.TryGetValue(ip, out var cached))
            return cached;

        try
        {
            // Use ip-api.com free tier (no API key needed, 45 requests/min)
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var response = await _client.GetAsync($"http://ip-api.com/json/{ip}?fields=country,countryCode,city,regionName,isp,lat,lon", cts.Token);

            if (response.IsSuccessStatusCode)
            {
                var json = await response.Content.ReadAsStringAsync(cts.Token);
                using var doc = JsonDocument.Parse(json);

                var root = doc.RootElement;
                var status = root.TryGetProperty("status", out var statusElem) ? statusElem.GetString() : "";
                if (status == "fail") return null;

                var geo = new GeoInfo(
                    ip,
                    root.TryGetProperty("country", out var c) ? c.GetString() ?? "Unknown" : "Unknown",
                    root.TryGetProperty("countryCode", out var cc) ? cc.GetString() ?? "??" : "??",
                    root.TryGetProperty("city", out var city) ? city.GetString() ?? "" : "",
                    root.TryGetProperty("regionName", out var r) ? r.GetString() ?? "" : "",
                    root.TryGetProperty("isp", out var isp) ? isp.GetString() ?? "" : "",
                    root.TryGetProperty("lat", out var lat) ? lat.GetDouble() : 0,
                    root.TryGetProperty("lon", out var lon) ? lon.GetDouble() : 0
                );

                _geoCache[ip] = geo;
                return geo;
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"GeoIP lookup error for {ip}: {ex.Message}");
        }

        return null;
    }

    private static bool IsPrivateIp(string ip)
    {
        try
        {
            var parts = ip.Split('.').Select(int.Parse).ToArray();
            if (parts[0] == 10) return true;
            if (parts[0] == 172 && parts[1] >= 16 && parts[1] <= 31) return true;
            if (parts[0] == 192 && parts[1] == 168) return true;
            if (parts[0] == 127) return true;
            return false;
        }
        catch
        {
            return false;
        }
    }
}
