using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json;
using SecKit.Core;
using SecKit.Models;

namespace SecKit.Modules.TrafficAnalysis;

/// <summary>Deploys fake honeypot endpoints to detect and log unauthorized access attempts.</summary>
public class HoneypotManager
{
    private readonly ConfigManager _config;
    private readonly ConcurrentBag<HoneypotHit> _hits = new();
    private HttpListener? _listener;
    private CancellationTokenSource? _cts;
    private bool _isRunning;

    /// <summary>Represents a hit on a honeypot endpoint.</summary>
    public record HoneypotHit(
        DateTime Timestamp, string Endpoint, string Method, string SourceIp,
        string UserAgent, string? Payload, Dictionary<string, string> Headers);

    // Common honeypot endpoints that attackers probe
    private static readonly string[] HoneypotEndpoints =
    {
        "/admin", "/administrator", "/wp-admin", "/wp-login.php",
        "/.env", "/.env.backup", "/.env.production", "/.env.local",
        "/config", "/config.json", "/configuration",
        "/backup", "/backups", "/backup.zip", "/backup.sql",
        "/db", "/database", "/phpmyadmin", "/phpMyAdmin", "/pma",
        "/.git/config", "/.git/HEAD", "/.svn/entries",
        "/actuator", "/actuator/env", "/actuator/health",
        "/api/admin", "/api/config", "/api/keys", "/api/secrets",
        "/.well-known/security.txt", "/security.txt",
        "/debug", "/debug/default", "/trace",
        "/console", "/terminal",
        "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
        "/solr/admin/cores",
        "/jenkins/script",
        "/api/v1/admin/users",
        "/graphql?query={__schema{types{name}}}",
        "/wp-json/wp/v2/users",
        "/.aws/credentials",
        "/credentials.json",
        "/id_rsa", "/id_ed25519",
        "/server-status",
    };

    public HoneypotManager(ConfigManager config)
    {
        _config = config;
    }

    /// <summary>Starts the honeypot HTTP server on the specified port.</summary>
    public void Start(int port = 8080)
    {
        if (_isRunning)
        {
            Logger.Warning("Honeypot is already running.");
            return;
        }

        _cts = new CancellationTokenSource();
        _listener = new HttpListener();
        _listener.Prefixes.Add($"http://+:{port}/");

        try
        {
            _listener.Start();
            _isRunning = true;
            Logger.Info($"🪤 Honeypot started on port {port} — listening for attackers...");
            Logger.WriteLine($"  Monitoring {HoneypotEndpoints.Length} decoy endpoints", ConsoleColor.Yellow);

            _ = Task.Run(() => ListenLoopAsync(_cts.Token));
        }
        catch (HttpListenerException ex)
        {
            Logger.Error($"Failed to start honeypot. Try running as administrator or use a different port: {ex.Message}");
        }
        catch (Exception ex)
        {
            Logger.Error($"Honeypot start error: {ex.Message}");
        }
    }

    /// <summary>Stops the honeypot server.</summary>
    public void Stop()
    {
        _cts?.Cancel();
        _listener?.Stop();
        _isRunning = false;
        Logger.Info($"🪤 Honeypot stopped. Total hits: {_hits.Count}");
    }

    private async Task ListenLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && _listener?.IsListening == true)
        {
            try
            {
                var context = await _listener.GetContextAsync().WaitAsync(ct);
                _ = Task.Run(() => HandleRequestAsync(context), ct);
            }
            catch (OperationCanceledException) { break; }
            catch (HttpListenerException) { break; }
            catch (Exception ex)
            {
                Logger.Debug($"Honeypot listener error: {ex.Message}");
            }
        }
    }

    private async Task HandleRequestAsync(HttpListenerContext context)
    {
        var request = context.Request;
        var path = request.Url?.AbsolutePath ?? "/";

        // Collect headers
        var headers = new Dictionary<string, string>();
        foreach (string? key in request.Headers.AllKeys)
        {
            if (key != null)
                headers[key] = request.Headers[key] ?? "";
        }

        // Read body if POST/PUT
        string? payload = null;
        if (request.HttpMethod == "POST" || request.HttpMethod == "PUT")
        {
            using var reader = new StreamReader(request.InputStream, request.ContentEncoding);
            payload = await reader.ReadToEndAsync();
            if (payload.Length > 5000) payload = payload[..5000] + "...";
        }

        var hit = new HoneypotHit(
            DateTime.UtcNow,
            path,
            request.HttpMethod,
            request.RemoteEndPoint?.Address?.ToString() ?? "unknown",
            request.UserAgent ?? "",
            payload,
            headers
        );

        _hits.Add(hit);

        // Alert on the hit
        var color = path switch
        {
            string p when p.Contains(".env") || p.Contains("config") => ConsoleColor.Red,
            string p when p.Contains("admin") || p.Contains("wp-") => ConsoleColor.Yellow,
            _ => ConsoleColor.DarkYellow
        };

        Logger.WriteLine($"  🚨 Honeypot hit: {hit.Method} {path} from {hit.SourceIp}", color);
        Logger.WriteLine($"     UA: {Truncate(hit.UserAgent, 80)}", ConsoleColor.Gray);

        if (!string.IsNullOrEmpty(payload))
        {
            Logger.WriteLine($"     Payload: {Truncate(payload, 100)}", ConsoleColor.DarkGray);
        }

        // Respond with a fake success to keep attackers interested
        var response = context.Response;
        response.StatusCode = 200;
        response.ContentType = "application/json";

        var fakeResponse = JsonSerializer.Serialize(new
        {
            status = "success",
            message = "Operation completed",
            data = new { id = 1, admin = true }
        });

        var buffer = Encoding.UTF8.GetBytes(fakeResponse);
        response.ContentLength64 = buffer.Length;
        await response.OutputStream.WriteAsync(buffer);
        response.OutputStream.Close();
    }

    /// <summary>Generates a scan result with all honeypot hits.</summary>
    public ScanResult GetResults()
    {
        var result = new ScanResult
        {
            ModuleName = "Honeypot Manager",
            TargetUrl = "honeypot",
            StartTime = DateTime.UtcNow.AddMinutes(-1),
            EndpointsTested = HoneypotEndpoints.Length
        };

        var hitsList = _hits.ToList();
        result.RequestsSent = hitsList.Count;

        Logger.WriteLine($"\n🪤 Honeypot Summary: {hitsList.Count} total hits", ConsoleColor.Cyan);

        // Group by endpoint
        var byEndpoint = hitsList.GroupBy(h => h.Endpoint).OrderByDescending(g => g.Count());
        foreach (var group in byEndpoint)
        {
            Logger.WriteLine($"  {group.Key,-40} {group.Count()} hits", ConsoleColor.White);
        }

        // Group by IP
        var byIp = hitsList.GroupBy(h => h.SourceIp).OrderByDescending(g => g.Count());
        Logger.WriteLine($"\n  Top attacker IPs:", ConsoleColor.Cyan);
        foreach (var group in byIp.Take(10))
        {
            Logger.WriteLine($"  {group.Key,-20} {group.Count()} hits", ConsoleColor.Red);
        }

        foreach (var hit in hitsList)
        {
            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "Honeypot Hit",
                Severity = hit.Endpoint.Contains(".env") || hit.Endpoint.Contains("config") ? "High" :
                           hit.Endpoint.Contains("admin") ? "Medium" : "Low",
                Url = hit.Endpoint,
                Parameter = "request",
                Payload = $"From: {hit.SourceIp}, UA: {Truncate(hit.UserAgent, 50)}",
                Description = $"Unauthorized access attempt to honeypot endpoint '{hit.Endpoint}' from {hit.SourceIp}.",
                Remediation = "Investigate the source IP. Consider blocking if repeated attempts. This is a decoy — no real data was exposed.",
                Module = "HoneypotManager",
                Confidence = 100
            });
        }

        result.Completed = true;
        result.EndTime = DateTime.UtcNow;
        return result;
    }

    /// <summary>Gets the total hit count.</summary>
    public int HitCount => _hits.Count;

    /// <summary>Whether the honeypot is running.</summary>
    public bool IsRunning => _isRunning;

    private static string Truncate(string value, int maxLength) =>
        value.Length > maxLength ? value[..maxLength] + "..." : value;
}
