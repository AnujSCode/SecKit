using System.Net.Sockets;
using System.Text.RegularExpressions;
using SecKit.Core;
using SecKit.Models;

namespace SecKit.Modules.Network;

/// <summary>Enhanced port scanner with banner grabbing, service version detection, OS fingerprinting, and CVE lookup.</summary>
public class EnhancedPortScanner
{
    private readonly ConfigManager _config;
    private readonly HttpClient _client;
    private readonly Dictionary<int, ServiceInfo> _serviceMap;

    private static readonly Dictionary<int, ServiceInfo> DefaultServiceMap = new()
    {
        [21] = new("FTP", "220", @"^220[\s-]"), [22] = new("SSH", "SSH", @"SSH-[\d.]+"),
        [25] = new("SMTP", "220", @"^220[\s-]"), [53] = new("DNS", null, null),
        [80] = new("HTTP", "HTTP", @"^HTTP/"), [110] = new("POP3", "+OK", @"^\+OK"),
        [143] = new("IMAP", "* OK", @"^\* OK"), [443] = new("HTTPS", null, null),
        [445] = new("SMB", null, null), [993] = new("IMAPS", null, null), [995] = new("POP3S", null, null),
        [1433] = new("MSSQL", null, null), [1521] = new("Oracle", null, null), [2049] = new("NFS", null, null),
        [3306] = new("MySQL", null, @"^.\x00\x00\x00"), [3389] = new("RDP", null, null),
        [5432] = new("PostgreSQL", null, null), [5900] = new("VNC", "RFB", @"^RFB "),
        [6379] = new("Redis", null, @"^-ERR|^\+PONG|^\+OK"), [8080] = new("HTTP-Alt", "HTTP", @"^HTTP/"),
        [8443] = new("HTTPS-Alt", null, null), [9090] = new("HTTP-Alt", "HTTP", @"^HTTP/"),
        [27017] = new("MongoDB", null, null),
    };

    public EnhancedPortScanner(HttpClient client, ConfigManager config)
    {
        _client = client;
        _config = config;
        // Try to load service map from config, fall back to defaults
        _serviceMap = LoadServiceMap(config) ?? DefaultServiceMap;
    }

    private static Dictionary<int, ServiceInfo>? LoadServiceMap(ConfigManager config)
    {
        var section = config.GetSection("advanced:enhancedPortScanServiceMap");
        if (!section.GetChildren().Any()) return null;
        var dict = new Dictionary<int, ServiceInfo>();
        foreach (var child in section.GetChildren())
        {
            if (int.TryParse(child.Key, out var port))
            {
                var name = child["Name"] ?? "Unknown";
                var banner = child["ExpectedBanner"];
                var regex = child["BannerRegex"];
                dict[port] = new ServiceInfo(name, string.IsNullOrEmpty(banner) ? null : banner, string.IsNullOrEmpty(regex) ? null : regex);
            }
        }
        return dict.Count > 0 ? dict : null;
    }

    public async Task<ScanResult> ScanAsync(string target)
    {
        var result = new ScanResult { ModuleName = "Enhanced Port Scanner", TargetUrl = target, StartTime = DateTime.UtcNow };
        try
        {
            var host = target.Replace("https://", "").Replace("http://", "").Split('/')[0].Split(':')[0];
            Logger.Info($"Starting enhanced port scan of: {host}");

            var commonPorts = _config.PortList;
            var openPorts = new List<(int Port, string Service, string? Banner)>();
            var semaphore = new SemaphoreSlim(50);
            var tasks = new List<Task>();

            foreach (var port in commonPorts)
            {
                await semaphore.WaitAsync();
                tasks.Add(ScanPortAsync(host, port, openPorts, semaphore, result));
            }
            await Task.WhenAll(tasks);

            var osFingerprint = await FingerprintOsAsync(host);
            result.Vulnerabilities.Add(new Vulnerability { Type = "OS Fingerprint", Severity = "Info", Url = host, Description = $"OS detection: {osFingerprint}", Module = "EnhancedPortScanner", Confidence = 60 });

            foreach (var (port, service, banner) in openPorts)
            {
                var cves = await LookupCvesAsync(service, banner);
                foreach (var cve in cves.Take(3))
                {
                    result.Vulnerabilities.Add(new Vulnerability { Type = $"CVE — {service}", Severity = cve.Severity, Url = $"{host}:{port}", Parameter = cve.Id, Description = $"{cve.Id}: {cve.Description}", Remediation = $"Update {service} to the latest patched version. Reference: {cve.Id}", Module = "EnhancedPortScanner", Confidence = 70 });
                }
            }

            if (openPorts.Count > 0)
            {
                result.Vulnerabilities.Add(new Vulnerability { Type = "Port Scan Result", Severity = openPorts.Count > 10 ? "High" : openPorts.Count > 5 ? "Medium" : "Low", Url = host, Description = $"Found {openPorts.Count} open ports: {string.Join(", ", openPorts.Select(p => $"{p.Port}/{p.Service}"))}", Remediation = openPorts.Count > 10 ? "Large number of open ports — reduce attack surface by closing unnecessary services." : "Review open ports and ensure all services are intentionally exposed and patched.", Module = "EnhancedPortScanner", Confidence = 95 });
            }
            else
            {
                result.Vulnerabilities.Add(new Vulnerability { Type = "Port Scan Result", Severity = "Info", Url = host, Description = "No common ports found open.", Module = "EnhancedPortScanner", Confidence = 85 });
            }
        }
        catch (Exception ex) { result.ErrorMessage = ex.Message; Logger.Error($"Enhanced port scan failed: {ex.Message}"); }

        result.EndTime = DateTime.UtcNow; result.Completed = result.ErrorMessage == null;
        return result;
    }

    private async Task ScanPortAsync(string host, int port, List<(int, string, string?)> openPorts, SemaphoreSlim semaphore, ScanResult result)
    {
        try
        {
            using var tcp = new TcpClient();
            var connectTask = tcp.ConnectAsync(host, port);
            if (await Task.WhenAny(connectTask, Task.Delay(TimeSpan.FromSeconds(2))) == connectTask)
            {
                await connectTask;
                var service = _serviceMap.TryGetValue(port, out var info) ? info.Name : "Unknown";
                openPorts.Add((port, service, null));

                string? banner = null;
                try
                {
                    using var stream = tcp.GetStream(); stream.ReadTimeout = 2000; stream.WriteTimeout = 2000;
                    await Task.Delay(500);
                    if (stream.DataAvailable) { var buffer = new byte[1024]; var bytesRead = await stream.ReadAsync(buffer, 0, 1024); if (bytesRead > 0) banner = System.Text.Encoding.ASCII.GetString(buffer, 0, bytesRead).Replace("\r", "").Replace("\n", " ").Trim(); }
                    else if (port is 80 or 8080 or 9090)
                    {
                        var httpProbe = System.Text.Encoding.ASCII.GetBytes($"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n");
                        await stream.WriteAsync(httpProbe); await Task.Delay(1000);
                        if (stream.DataAvailable) { var buffer = new byte[2048]; var bytesRead = await stream.ReadAsync(buffer, 0, 2048); banner = System.Text.Encoding.ASCII.GetString(buffer, 0, bytesRead).Split('\n')[0].Trim(); }
                    }
                }
                catch { }

                result.Vulnerabilities.Add(new Vulnerability { Type = "Open Port", Severity = "Medium", Url = $"{host}:{port}", Parameter = $"Port {port}/{service}", Description = $"Port {port} ({service}) is open.{(banner != null ? $" [{banner}]" : "")}", Evidence = banner ?? "", Remediation = $"If {service} is not needed, close port {port} in the firewall.", Module = "EnhancedPortScanner", Confidence = 100 });
            }
        }
        catch { }
        finally { semaphore.Release(); }
    }

    private async Task<string> FingerprintOsAsync(string host)
    {
        try
        {
            using var tcp = new TcpClient();
            var connectTask = tcp.ConnectAsync(host, 80);
            if (await Task.WhenAny(connectTask, Task.Delay(3000)) == connectTask)
            {
                await connectTask;
                var ping = new System.Net.NetworkInformation.Ping();
                var reply = await ping.SendPingAsync(host, 2000);
                if (reply.Status == System.Net.NetworkInformation.IPStatus.Success)
                {
                    var ttl = reply.Options?.Ttl ?? 0;
                    return ttl switch { <= 64 => "Linux/Unix (TTL ≤64)", <= 128 => "Windows (TTL ≤128)", <= 254 => "Solaris/BSD (TTL ≤254)", _ => "Unknown (could not fingerprint)" };
                }
                try { var response = await _client.GetAsync($"http://{host}/"); var serverHeader = response.Headers.Server?.ToString() ?? ""; if (!string.IsNullOrEmpty(serverHeader)) return $"Web server: {serverHeader}"; } catch { }
                return "Responsive (could not fingerprint OS)";
            }
            return "No response — OS fingerprint unavailable";
        }
        catch { return "Unknown (fingerprint failed)"; }
    }

    private async Task<List<(string Id, string Severity, string Description)>> LookupCvesAsync(string service, string? banner)
    {
        var cves = new List<(string, string, string)>();
        if (string.IsNullOrEmpty(banner)) return cves;
        try
        {
            var version = ExtractVersion(banner);
            if (version == null) return cves;
            var keyword = $"{service} {version}";
            var url = $"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={Uri.EscapeDataString(keyword)}&resultsPerPage=3";
            var response = await _client.GetStringAsync(url);
            var cveMatches = Regex.Matches(response, @"""id""\s*:\s*""(CVE-\d{4}-\d+)""");
            var descMatches = Regex.Matches(response, @"""value""\s*:\s*""([^""]{50,300})""", RegexOptions.Singleline);
            var sevMatches = Regex.Matches(response, @"""baseSeverity""\s*:\s*""(\w+)""");
            for (int i = 0; i < Math.Min(3, cveMatches.Count); i++)
            {
                var cveId = cveMatches[i].Groups[1].Value;
                var desc = i < descMatches.Count ? descMatches[i].Groups[1].Value : "See NVD for details";
                var sev = i < sevMatches.Count ? sevMatches[i].Groups[1].Value : "MEDIUM";
                if (desc.Length > 200) desc = desc[..200] + "...";
                cves.Add((cveId, sev, desc));
            }
        }
        catch { }
        return cves;
    }

    private static string? ExtractVersion(string banner)
    {
        var apacheMatch = Regex.Match(banner, @"Apache/([\d.]+)"); if (apacheMatch.Success) return apacheMatch.Groups[1].Value;
        var sshMatch = Regex.Match(banner, @"OpenSSH[_]([\d.]+)"); if (sshMatch.Success) return sshMatch.Groups[1].Value;
        var nginxMatch = Regex.Match(banner, @"nginx/([\d.]+)"); if (nginxMatch.Success) return nginxMatch.Groups[1].Value;
        var genericMatch = Regex.Match(banner, @"([\w-]+)/([\d.]+)"); if (genericMatch.Success) return genericMatch.Groups[2].Value;
        return null;
    }

    private record ServiceInfo(string Name, string? ExpectedBanner, string? BannerRegex);
}
