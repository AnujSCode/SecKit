using System.Diagnostics;
using SecKit.Core;
using SecKit.Models;

namespace SecKit.Modules.ServerHardening;

/// <summary>
/// Audits cron jobs and systemd timers for security issues:
/// writable cron files, suspicious cron entries (downloading from /tmp,
/// curl/wget to sketchy URLs), and insecure systemd timer configurations.
/// </summary>
public class CronScanner
{
    // Cron directories to check
    private static readonly string[] CronDirs =
    {
        "/etc/crontab",
        "/etc/cron.d",
        "/etc/cron.hourly",
        "/etc/cron.daily",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/var/spool/cron/crontabs",
        "/var/spool/cron"
    };

    // Suspicious patterns in cron entries
    private static readonly string[] SuspiciousPatterns =
    {
        "/tmp/", "/dev/shm/", "/var/tmp/",
        "curl", "wget", "fetch",
        "nc -e", "nc -l", "ncat -e",
        "bash -i >&", "python -c", "perl -e", "ruby -e",
        "base64 -d", "eval", "exec",
        ".onion", "tor2web",
        "chmod +x", "chmod 777",
        "iptables -F", "ufw disable"
    };

    // Known sketchy domains/IP patterns
    private static readonly string[] SketchyPatterns =
    {
        ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq",
        "pastebin.com", "pastie.org", "ghostbin.com",
        "hastebin.com", "termbin.com",
        "0.0.0.0", "127.0.0.1:"
    };

    /// <summary>
    /// Audits cron jobs and systemd timers on the target system.
    /// </summary>
    /// <param name="target">Target hostname or IP (typically localhost).</param>
    /// <returns>ScanResult with cron audit findings.</returns>
    public async Task<ScanResult> ScanAsync(string target)
    {
        var result = new ScanResult
        {
            ModuleName = "Cron Scanner",
            TargetUrl = target,
            StartTime = DateTime.UtcNow
        };

        try
        {
            Logger.Info("Auditing cron jobs and systemd timers...");

            var tasks = new[]
            {
                AuditCronFilePermissionsAsync(result),
                AuditSuspiciousCronEntriesAsync(result),
                AuditSystemdTimersAsync(result)
            };

            await Task.WhenAll(tasks);

            result.Completed = true;
            Logger.Info($"Cron audit complete: {result.Vulnerabilities.Count} findings.");
        }
        catch (Exception ex)
        {
            result.ErrorMessage = ex.Message;
            Logger.Error($"Cron scanner failed: {ex.Message}");
        }

        result.EndTime = DateTime.UtcNow;
        return result;
    }

    /// <summary>Checks for writable cron files and directories.</summary>
    private static async Task AuditCronFilePermissionsAsync(ScanResult result)
    {
        try
        {
            foreach (var dir in CronDirs)
            {
                if (!Directory.Exists(dir) && !File.Exists(dir)) continue;

                // Check for world-writable cron files
                var output = await RunCommandAsync(
                    $"find '{dir}' -perm /o+w -type f 2>/dev/null");

                if (!string.IsNullOrWhiteSpace(output))
                {
                    foreach (var file in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                    {
                        var trimmed = file.Trim();
                        if (string.IsNullOrWhiteSpace(trimmed)) continue;

                        result.Vulnerabilities.Add(new Vulnerability
                        {
                            Type = "Writable Cron File",
                            Severity = "Critical",
                            Description = $"Cron file '{trimmed}' is world-writable. Any user can add malicious cron jobs for persistence or privilege escalation.",
                            Remediation = $"Run: chmod o-w '{trimmed}' and verify ownership: chown root:root '{trimmed}'",
                            Evidence = trimmed,
                            Module = "CronScanner",
                            Confidence = 95
                        });
                    }
                }

                // Check for group-writable cron files
                output = await RunCommandAsync(
                    $"find '{dir}' -perm /g+w -type f 2>/dev/null");

                if (!string.IsNullOrWhiteSpace(output))
                {
                    foreach (var file in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                    {
                        var trimmed = file.Trim();
                        if (string.IsNullOrWhiteSpace(trimmed)) continue;

                        // Check if group is root
                        var groupOutput = await RunCommandAsync($"stat -c '%G' '{trimmed}' 2>/dev/null");
                        if (groupOutput.Trim() != "root")
                        {
                            result.Vulnerabilities.Add(new Vulnerability
                            {
                                Type = "Group-Writable Cron File",
                                Severity = "High",
                                Description = $"Cron file '{trimmed}' is group-writable by group '{groupOutput.Trim()}'.",
                                Remediation = $"Run: chmod g-w '{trimmed}'",
                                Evidence = $"File: {trimmed} | Group: {groupOutput.Trim()}",
                                Module = "CronScanner",
                                Confidence = 85
                            });
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"Cron permissions audit failed: {ex.Message}");
        }
    }

    /// <summary>Scans cron entries for suspicious patterns.</summary>
    private static async Task AuditSuspiciousCronEntriesAsync(ScanResult result)
    {
        try
        {
            // Collect all cron entries from various sources
            var allEntries = new List<(string Source, string Line)>();

            // System crontab
            var sysCrontab = await RunCommandAsync("cat /etc/crontab 2>/dev/null");
            if (!string.IsNullOrWhiteSpace(sysCrontab))
            {
                foreach (var line in sysCrontab.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                {
                    var trimmed = line.Trim();
                    if (!string.IsNullOrWhiteSpace(trimmed) && !trimmed.StartsWith('#'))
                        allEntries.Add(("/etc/crontab", trimmed));
                }
            }

            // Cron.d entries
            if (Directory.Exists("/etc/cron.d"))
            {
                var cronDOutput = await RunCommandAsync(
                    "grep -rhv '^#' /etc/cron.d/* 2>/dev/null | grep -v '^$'");
                if (!string.IsNullOrWhiteSpace(cronDOutput))
                {
                    foreach (var line in cronDOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                        allEntries.Add(("/etc/cron.d", line.Trim()));
                }
            }

            // User crontabs
            if (Directory.Exists("/var/spool/cron/crontabs"))
            {
                var userCrons = await RunCommandAsync(
                    "grep -rhv '^#' /var/spool/cron/crontabs/* 2>/dev/null | grep -v '^$'");
                if (!string.IsNullOrWhiteSpace(userCrons))
                {
                    foreach (var line in userCrons.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                        allEntries.Add(("/var/spool/cron/crontabs", line.Trim()));
                }
            }

            // Cron.hourly/daily/weekly/monthly directories
            foreach (var dir in new[] { "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly" })
            {
                if (!Directory.Exists(dir)) continue;

                var scriptOutput = await RunCommandAsync(
                    $"grep -rl '' '{dir}'/* 2>/dev/null | xargs cat 2>/dev/null");
                if (!string.IsNullOrWhiteSpace(scriptOutput))
                {
                    foreach (var line in scriptOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                    {
                        var trimmed = line.Trim();
                        if (!string.IsNullOrWhiteSpace(trimmed) && !trimmed.StartsWith('#'))
                            allEntries.Add((dir, trimmed));
                    }
                }
            }

            // Analyze collected entries
            var seen = new HashSet<string>();
            foreach (var (source, line) in allEntries)
            {
                foreach (var pattern in SuspiciousPatterns)
                {
                    if (line.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        var dedupe = $"{pattern}:{line.GetHashCode()}";
                        if (!seen.Add(dedupe)) continue;

                        var severity = pattern switch
                        {
                            "nc -e" or "nc -l" or "ncat -e" or "bash -i >&" => "Critical",
                            "base64 -d" or "eval" or "exec" => "High",
                            "python -c" or "perl -e" or "ruby -e" => "High",
                            "curl" or "wget" or "fetch" => "Medium",
                            _ => "Medium"
                        };

                        result.Vulnerabilities.Add(new Vulnerability
                        {
                            Type = "Suspicious Cron Entry",
                            Severity = severity,
                            Description = $"Suspicious cron entry in {source}: pattern '{pattern}' detected. Line: {line}",
                            Remediation = "Investigate this cron entry. Remove if unauthorized. Check for signs of compromise.",
                            Evidence = $"Source: {source} | Pattern: {pattern} | {line}",
                            Module = "CronScanner",
                            Confidence = 55
                        });
                        break;
                    }
                }

                // Check for sketchy URLs
                foreach (var sketchy in SketchyPatterns)
                {
                    if (line.Contains(sketchy, StringComparison.OrdinalIgnoreCase))
                    {
                        var dedupe = $"sketchy:{line.GetHashCode()}";
                        if (!seen.Add(dedupe)) continue;

                        result.Vulnerabilities.Add(new Vulnerability
                        {
                            Type = "Suspicious Cron URL",
                            Severity = "High",
                            Description = $"Cron entry in {source} references potentially sketchy destination: {sketchy}. Line: {line}",
                            Remediation = "Investigate this cron entry immediately. Remove if unauthorized.",
                            Evidence = $"Source: {source} | Indicator: {sketchy} | {line}",
                            Module = "CronScanner",
                            Confidence = 50
                        });
                        break;
                    }
                }
            }

            if (allEntries.Count > 0)
            {
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "Cron Entries Summary",
                    Severity = "Info",
                    Description = $"Total cron entries reviewed: {allEntries.Count} from {CronDirs.Length} locations.",
                    Remediation = "Regularly review cron jobs and remove unused or unauthorized entries.",
                    Evidence = $"Entries: {allEntries.Count}",
                    Module = "CronScanner",
                    Confidence = 90
                });
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"Suspicious cron entries audit failed: {ex.Message}");
        }
    }

    /// <summary>Audits systemd timers for security-relevant configurations.</summary>
    private static async Task AuditSystemdTimersAsync(ScanResult result)
    {
        try
        {
            // List all timers
            var output = await RunCommandAsync("systemctl list-timers --all --no-pager 2>/dev/null");

            if (string.IsNullOrWhiteSpace(output))
            {
                Logger.Debug("systemctl not available or no timers found.");
                return;
            }

            var timerCount = 0;
            foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                if (line.Contains(".timer", StringComparison.OrdinalIgnoreCase))
                    timerCount++;
            }

            if (timerCount > 0)
            {
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "Systemd Timers Summary",
                    Severity = "Info",
                    Description = $"Found {timerCount} systemd timers. Review for unnecessary or unauthorized timers.",
                    Remediation = "Check timer configs: systemctl list-timers. Disable unnecessary: systemctl disable --now <timer>",
                    Evidence = $"Count: {timerCount}",
                    Module = "CronScanner",
                    Confidence = 90
                });
            }

            // Check for user-level systemd timers (can run without root for persistence)
            var userTimersOutput = await RunCommandAsync(
                "find /home -path '*/systemd/user/*.timer' -type f 2>/dev/null || true");

            if (!string.IsNullOrWhiteSpace(userTimersOutput))
            {
                var userTimers = userTimersOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                foreach (var timer in userTimers)
                {
                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = "User Systemd Timer",
                        Severity = "Low",
                        Description = $"User systemd timer found: {timer.Trim()}. User-level timers can run without root and survive reboots.",
                        Remediation = "Review the timer and its service for authorized usage.",
                        Evidence = timer.Trim(),
                        Module = "CronScanner",
                        Confidence = 70
                    });
                }
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"Systemd timer audit failed: {ex.Message}");
        }
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
