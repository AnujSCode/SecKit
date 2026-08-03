using System.Diagnostics;
using SecKit.Core;
using SecKit.Models;

namespace SecKit.Modules.ServerHardening;

/// <summary>
/// Audits running processes and network listeners for security issues:
/// listening ports mapped to processes, known-vulnerable service versions,
/// services running as root, and unusual/heuristic process detection.
/// </summary>
public class ProcessAuditor
{
    // Known-vulnerable version patterns (old/end-of-life services)
    private static readonly (string Pattern, string Name, string Cve)[] KnownVulnerableVersions =
    {
        ("OpenSSH_5", "OpenSSH ≤ 5.x", "Multiple CVEs — upgrade to 9.x"),
        ("OpenSSH_6", "OpenSSH ≤ 6.x", "Multiple CVEs — upgrade to 9.x"),
        ("OpenSSH_7.0", "OpenSSH 7.0-7.3", "CVE-2016-10009, CVE-2016-10012 — upgrade to 9.x"),
        ("Apache/2.2", "Apache 2.2.x", "EOL — upgrade to 2.4.x"),
        ("Apache/2.4.0", "Apache 2.4.0-2.4.6", "Multiple early CVEs — upgrade to latest 2.4.x"),
        ("nginx/0.", "nginx 0.x", "EOL — upgrade to latest stable"),
        ("nginx/1.0", "nginx 1.0-1.6", "EOL — upgrade to latest stable"),
        ("nginx/1.8", "nginx 1.8", "EOL — upgrade to latest stable"),
        ("MySQL 5.5", "MySQL 5.5", "EOL — upgrade to 8.0+"),
        ("MySQL 5.6", "MySQL 5.6", "EOL — upgrade to 8.0+"),
        ("Redis 2.", "Redis 2.x", "EOL — upgrade to 7.x"),
        ("Redis 3.", "Redis 3.x", "EOL — upgrade to 7.x"),
        ("Redis 4.", "Redis 4.x", "EOL — upgrade to 7.x"),
        ("PHP 5.", "PHP 5.x", "EOL — upgrade to 8.x"),
        ("PHP 7.0", "PHP 7.0", "EOL — upgrade to 8.x"),
        ("PHP 7.1", "PHP 7.1", "EOL — upgrade to 8.x"),
        ("PHP 7.2", "PHP 7.2", "EOL — upgrade to 8.x"),
        ("PHP 7.3", "PHP 7.3", "EOL — upgrade to 8.x"),
    };

    // Suspicious process name patterns (heuristic)
    private static readonly string[] SuspiciousProcessPatterns =
    {
        "miner", "minerd", "xmrig", "cgminer", "bfgminer", "cpuminer",
        "bot", "backdoor", "bind-shell", "reverse-shell", "shell.php",
        "ransomware", "cryptominer", "kinsing", "pwnrig", "kdevtmpfs",
        "tshd", "wnTKYg", "mvdsv", "ddos", "flood"
    };

    // Services that should NOT run as root
    private static readonly string[] ServicesNotAsRoot =
    {
        "nginx", "apache2", "httpd", "mysqld", "mariadbd", "postgres",
        "redis-server", "mongod", "docker", "containerd", "named",
        "bind", "sshd", "cron", "rsyslog"
    };

    /// <summary>
    /// Audits running processes and network listeners on the target system.
    /// </summary>
    /// <param name="target">Target hostname or IP (typically localhost).</param>
    /// <returns>ScanResult with process audit findings.</returns>
    public async Task<ScanResult> ScanAsync(string target)
    {
        var result = new ScanResult
        {
            ModuleName = "Process Auditor",
            TargetUrl = target,
            StartTime = DateTime.UtcNow
        };

        try
        {
            Logger.Info("Auditing processes and network listeners...");

            var tasks = new[]
            {
                AuditListeningPortsAsync(result),
                AuditServicesRunningAsRootAsync(result),
                AuditVulnerableServicesAsync(result),
                AuditSuspiciousProcessesAsync(result)
            };

            await Task.WhenAll(tasks);

            result.Completed = true;
            Logger.Info($"Process audit complete: {result.Vulnerabilities.Count} findings.");
        }
        catch (Exception ex)
        {
            result.ErrorMessage = ex.Message;
            Logger.Error($"Process auditor failed: {ex.Message}");
        }

        result.EndTime = DateTime.UtcNow;
        return result;
    }

    /// <summary>Lists listening TCP ports and maps them to processes.</summary>
    private static async Task AuditListeningPortsAsync(ScanResult result)
    {
        try
        {
            // Try ss first (modern), fall back to netstat
            var output = await RunCommandAsync("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null");

            if (string.IsNullOrWhiteSpace(output))
            {
                Logger.Debug("Could not list listening ports (ss/netstat not available or no permission).");
                return;
            }

            var entries = ParseListeningPorts(output);

            // Sensitive ports that shouldn't be exposed
            var sensitivePorts = new Dictionary<int, string>
            {
                { 3306, "MySQL/MariaDB" },
                { 5432, "PostgreSQL" },
                { 6379, "Redis" },
                { 27017, "MongoDB" },
                { 9200, "Elasticsearch" },
                { 11211, "Memcached" },
                { 2375, "Docker (unencrypted)" },
                { 2376, "Docker (TLS)" },
            };

            foreach (var (port, process) in entries)
            {
                // Check for sensitive ports listening on all interfaces
                if (sensitivePorts.TryGetValue(port, out var serviceName))
                {
                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = "Exposed Database/Service Port",
                        Severity = "High",
                        Description = $"{serviceName} is listening on port {port} (process: {process}). This port should not be exposed to public networks.",
                        Remediation = $"Bind {serviceName} to localhost (127.0.0.1) or restrict access with firewall rules.",
                        Evidence = $"Port: {port} | Process: {process} | Service: {serviceName}",
                        Module = "ProcessAuditor",
                        Confidence = 85
                    });
                }
            }

            // Summary
            if (entries.Count > 0)
            {
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "Listening Ports Summary",
                    Severity = "Info",
                    Description = $"Found {entries.Count} listening TCP ports.",
                    Remediation = "Review all listening services and disable unnecessary ones.",
                    Evidence = $"Count: {entries.Count}",
                    Module = "ProcessAuditor",
                    Confidence = 95
                });
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"Listening port audit failed: {ex.Message}");
        }
    }

    /// <summary>Checks for services running as root that shouldn't be.</summary>
    private static async Task AuditServicesRunningAsRootAsync(ScanResult result)
    {
        try
        {
            // Use ps to find processes running as root
            var output = await RunCommandAsync("ps aux 2>/dev/null | grep -E '^root'");

            if (string.IsNullOrWhiteSpace(output)) return;

            foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                foreach (var svc in ServicesNotAsRoot)
                {
                    if (line.Contains(svc, StringComparison.OrdinalIgnoreCase))
                    {
                        // Extract process name for evidence
                        var columns = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                        var command = columns.Length > 10
                            ? string.Join(' ', columns.Skip(10))
                            : line;

                        result.Vulnerabilities.Add(new Vulnerability
                        {
                            Type = "Service Running as Root",
                            Severity = "High",
                            Description = $"{svc} is running as root. If compromised, an attacker gains full system access.",
                            Remediation = $"Configure {svc} to run under a dedicated unprivileged user account.",
                            Evidence = $"Process: {command.Trim()}",
                            Module = "ProcessAuditor",
                            Confidence = 85
                        });
                        break; // Only flag once per service
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"Root service audit failed: {ex.Message}");
        }
    }

    /// <summary>Checks for services with known vulnerable versions.</summary>
    private static async Task AuditVulnerableServicesAsync(ScanResult result)
    {
        try
        {
            // Try to get version strings from common services
            var checks = new (string Command, string Service)[] {
                ("ssh -V 2>&1 | head -1", "OpenSSH"),
                ("apache2 -v 2>&1 | head -1 || httpd -v 2>&1 | head -1", "Apache"),
                ("nginx -v 2>&1", "nginx"),
                ("mysql --version 2>/dev/null | head -1", "MySQL"),
                ("redis-server --version 2>/dev/null | head -1", "Redis"),
                ("php --version 2>/dev/null | head -1", "PHP"),
            };

            foreach (var (command, service) in checks)
            {
                var output = await RunCommandAsync(command);
                if (string.IsNullOrWhiteSpace(output)) continue;

                foreach (var (pattern, name, cve) in KnownVulnerableVersions)
                {
                    if (output.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        result.Vulnerabilities.Add(new Vulnerability
                        {
                            Type = "Vulnerable Service Version",
                            Severity = "High",
                            Description = $"{name} detected: {output.Trim()}. {cve}",
                            Remediation = $"Upgrade {service} to the latest stable version.",
                            Evidence = output.Trim(),
                            Module = "ProcessAuditor",
                            Confidence = 80
                        });
                        break;
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"Vulnerable service audit failed: {ex.Message}");
        }
    }

    /// <summary>Heuristic check for suspicious processes (mining, backdoors, etc.).</summary>
    private static async Task AuditSuspiciousProcessesAsync(ScanResult result)
    {
        try
        {
            var output = await RunCommandAsync("ps aux --no-headers 2>/dev/null");

            if (string.IsNullOrWhiteSpace(output)) return;

            foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                foreach (var pattern in SuspiciousProcessPatterns)
                {
                    if (line.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        var columns = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                        var user = columns.Length > 0 ? columns[0] : "unknown";
                        var pid = columns.Length > 1 ? columns[1] : "unknown";
                        var command = columns.Length > 10
                            ? string.Join(' ', columns.Skip(10))
                            : line;

                        result.Vulnerabilities.Add(new Vulnerability
                        {
                            Type = "Suspicious Process",
                            Severity = "Critical",
                            Description = $"Suspicious process detected matching pattern '{pattern}': {command.Trim()} (PID: {pid}, User: {user})",
                            Remediation = "Investigate immediately. Kill process if confirmed malicious: kill -9 <PID>. Check for persistence mechanisms.",
                            Evidence = $"Pattern: {pattern} | PID: {pid} | User: {user} | Cmd: {command.Trim()}",
                            Module = "ProcessAuditor",
                            Confidence = 60
                        });
                        break;
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"Suspicious process audit failed: {ex.Message}");
        }
    }

    /// <summary>Parses ss/netstat output into (port, process) pairs.</summary>
    private static List<(int Port, string Process)> ParseListeningPorts(string output)
    {
        var entries = new List<(int Port, string Process)>();

        foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            // Skip header lines
            if (line.StartsWith("State", StringComparison.OrdinalIgnoreCase) ||
                line.StartsWith("Netid", StringComparison.OrdinalIgnoreCase) ||
                line.StartsWith("Proto", StringComparison.OrdinalIgnoreCase) ||
                line.StartsWith("Active", StringComparison.OrdinalIgnoreCase))
                continue;

            // ss format: "LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1234,fd=3))"
            // netstat format: "tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN 1234/sshd"

            // Try ss format first (contains "users:")
            var usersIdx = line.IndexOf("users:", StringComparison.Ordinal);
            if (usersIdx >= 0)
            {
                var portMatch = ExtractPort(line);
                if (!portMatch.HasValue) continue;

                var processSection = line[usersIdx..];
                var procNameStart = processSection.IndexOf("(\"", StringComparison.Ordinal);
                if (procNameStart >= 0)
                {
                    var procNameEnd = processSection.IndexOf("\"", procNameStart + 2, StringComparison.Ordinal);
                    var processName = procNameEnd > procNameStart
                        ? processSection.Substring(procNameStart + 2, procNameEnd - procNameStart - 2)
                        : "unknown";

                    entries.Add((portMatch.Value, processName));
                }
                continue;
            }

            // Try netstat format
            var columns = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            if (columns.Length >= 7)
            {
                var portMatch = ExtractPort(columns[3]);
                if (!portMatch.HasValue) continue;

                var process = columns.Length >= 7 && columns[6].Contains('/')
                    ? columns[6].Split('/').LastOrDefault() ?? "unknown"
                    : columns[6];

                entries.Add((portMatch.Value, process));
            }
        }

        return entries;
    }

    /// <summary>Extracts port number from an address:port string like "0.0.0.0:22" or "[::]:22".</summary>
    private static int? ExtractPort(string address)
    {
        try
        {
            // Handle IPv6: [::]:22
            var lastColon = address.LastIndexOf(':');
            if (lastColon < 0) return null;

            var portStr = address[(lastColon + 1)..];
            if (int.TryParse(portStr, out var port) && port > 0 && port < 65536)
                return port;
        }
        catch { }
        return null;
    }

    /// <summary>Runs a shell command and returns stdout.</summary>
    private static async Task<string> RunCommandAsync(string command)
    {
        try
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "bash",
                    Arguments = $"-c \"{command.Replace("\"", "\\\"")}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };

            process.Start();
            var output = await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();
            return output;
        }
        catch (Exception ex)
        {
            Logger.Debug($"Command failed: {command} - {ex.Message}");
            return string.Empty;
        }
    }
}
