using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using SecKit.Core;
using SecKit.Models;

namespace SecKit.Modules.NetworkScanner;

/// <summary>Multi-threaded TCP port scanner for discovering open ports on target hosts.</summary>
public class PortScanner
{
    private readonly ConfigManager _config;
    private int _startPort;
    private int _endPort;
    private int _threads;

    private static readonly Dictionary<int, string> CommonPorts = new()
    {
        {21, "FTP"}, {22, "SSH"}, {23, "Telnet"}, {25, "SMTP"}, {53, "DNS"},
        {80, "HTTP"}, {110, "POP3"}, {111, "RPC"}, {135, "RPC"},
        {139, "NetBIOS"}, {143, "IMAP"}, {443, "HTTPS"}, {445, "SMB"},
        {993, "IMAPS"}, {995, "POP3S"}, {1433, "MSSQL"}, {1521, "Oracle"},
        {1723, "PPTP"}, {3306, "MySQL"}, {3389, "RDP"}, {5432, "PostgreSQL"},
        {5900, "VNC"}, {6379, "Redis"}, {8080, "HTTP-Alt"}, {8443, "HTTPS-Alt"},
        {9200, "Elasticsearch"}, {11211, "Memcached"}, {27017, "MongoDB"},
        {5000, "Docker Registry"}, {9090, "Prometheus"},
        {3000, "Grafana/Node"}, {4000, "Jekyll"}, {8000, "Dev Server"},
        {9000, "PHP-FPM"}, {5001, "Synology"}, {4443, "Synology HTTPS"},
        {6443, "Kubernetes API"}, {2375, "Docker"}, {2376, "Docker TLS"},
    };

    public PortScanner(ConfigManager config)
    {
        _config = config;
        _startPort = config.PortRangeStart;
        _endPort = config.PortRangeEnd;
        _threads = config.Threads;
    }

    /// <summary>Scans a target host for open TCP ports.</summary>
    public async Task<ScanResult> ScanAsync(string target)
    {
        var result = new ScanResult
        {
            ModuleName = "Port Scanner",
            TargetUrl = target,
            StartTime = DateTime.UtcNow
        };

        try
        {
            var host = ExtractHost(target);
            result.EndpointsTested = 1;

            Logger.Info($"Scanning {host} ports {_startPort}-{_endPort} with {_threads} threads...");

            var openPorts = new ConcurrentBag<(int Port, string Service)>();

            using var semaphore = new SemaphoreSlim(_threads);
            var tasks = new List<Task>();

            for (int port = _startPort; port <= _endPort; port++)
            {
                var currentPort = port;
                await semaphore.WaitAsync();

                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        var isOpen = await IsPortOpenAsync(host, currentPort);
                        if (isOpen)
                        {
                            var service = CommonPorts.TryGetValue(currentPort, out var svc) ? svc : "Unknown";
                            openPorts.Add((currentPort, service));
                            Logger.WriteLine($"  Open port {currentPort} ({service})", ConsoleColor.Green);
                        }
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                }));
            }

            await Task.WhenAll(tasks);

            result.RequestsSent = _endPort - _startPort + 1;

            foreach (var (port, service) in openPorts.OrderBy(p => p.Port))
            {
                var severity = port switch
                {
                    21 or 23 or 139 or 445 or 3389 => "High",
                    22 or 1433 or 3306 or 5432 or 6379 or 27017 => "Medium",
                    _ => "Low"
                };

                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "Open Port",
                    Severity = severity,
                    Url = host + ":" + port,
                    Parameter = "Port " + port,
                    Payload = service,
                    Description = "Port " + port + "/tcp is open (" + service + ").",
                    Remediation = "Close unnecessary ports in firewall. Restrict access to sensitive services.",
                    Module = "PortScanner",
                    Confidence = 100
                });
            }

            Logger.Info($"Port scan complete: {openPorts.Count} open ports found.");
            result.Completed = true;
        }
        catch (Exception ex)
        {
            result.ErrorMessage = ex.Message;
            Logger.Error("Port scanner failed: " + ex.Message);
        }

        result.EndTime = DateTime.UtcNow;
        return result;
    }

    private async Task<bool> IsPortOpenAsync(string host, int port)
    {
        try
        {
            using var tcpClient = new TcpClient();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            await tcpClient.ConnectAsync(host, port, cts.Token);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string ExtractHost(string url)
    {
        try
        {
            if (url.Contains("://"))
            {
                var uri = new Uri(url);
                return uri.Host;
            }

            var colonIndex = url.LastIndexOf(':');
            if (colonIndex > 0)
            {
                var possiblePort = url[(colonIndex + 1)..];
                if (int.TryParse(possiblePort, out _))
                    return url[..colonIndex];
            }

            return url;
        }
        catch
        {
            return url;
        }
    }
}
