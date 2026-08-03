using System.Diagnostics;
using SecKit.Core;
using SecKit.Models;

namespace SecKit.Modules.ServerHardening;

/// <summary>
/// Audits user accounts for security issues: UID 0 users, empty passwords,
/// sudoers configuration, password aging, stale accounts, and sensitive group memberships.
/// </summary>
public class UserAuditor
{
    private static readonly string[] SensitiveGroups =
    {
        "sudo", "wheel", "docker", "adm", "admin", "root",
        "shadow", "disk", "lpadmin", "systemd-journal"
    };

    /// <summary>
    /// Audits user accounts on the target system for hardening weaknesses.
    /// </summary>
    /// <param name="target">Target hostname or IP (typically localhost).</param>
    /// <returns>ScanResult with user account audit findings.</returns>
    public async Task<ScanResult> ScanAsync(string target)
    {
        var result = new ScanResult
        {
            ModuleName = "User Auditor",
            TargetUrl = target,
            StartTime = DateTime.UtcNow
        };

        try
        {
            Logger.Info("Auditing user accounts...");

            var tasks = new[]
            {
                AuditUidZeroUsersAsync(result),
                AuditEmptyPasswordsAsync(result),
                AuditSudoersAsync(result),
                AuditPasswordAgingAsync(result),
                AuditStaleAccountsAsync(result),
                AuditSensitiveGroupMembershipsAsync(result)
            };

            await Task.WhenAll(tasks);

            result.Completed = true;
            Logger.Info($"User audit complete: {result.Vulnerabilities.Count} findings.");
        }
        catch (Exception ex)
        {
            result.ErrorMessage = ex.Message;
            Logger.Error($"User auditor failed: {ex.Message}");
        }

        result.EndTime = DateTime.UtcNow;
        return result;
    }

    /// <summary>Checks for users with UID 0 (root equivalent).</summary>
    private static async Task AuditUidZeroUsersAsync(ScanResult result)
    {
        try
        {
            var output = await RunCommandAsync("awk -F: '($3 == 0) {print $1}' /etc/passwd");

            if (string.IsNullOrWhiteSpace(output)) return;

            var users = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            var nonRootUsers = users.Where(u => u.Trim() != "root").ToList();

            foreach (var user in nonRootUsers)
            {
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "UID 0 User",
                    Severity = "Critical",
                    Description = $"User '{user.Trim()}' has UID 0 (root equivalent). This is a backdoor risk.",
                    Remediation = $"Change the UID: usermod -u <new-uid> {user.Trim()}. Only 'root' should have UID 0.",
                    Evidence = $"User: {user.Trim()} UID: 0",
                    Module = "UserAuditor",
                    Confidence = 95
                });
            }

            if (users.Length > 1 || nonRootUsers.Count > 0)
            {
                Logger.Warning($"Found {nonRootUsers.Count} non-root users with UID 0");
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"UID 0 check failed: {ex.Message}");
        }
    }

    /// <summary>Checks for users with empty passwords in /etc/shadow.</summary>
    private static async Task AuditEmptyPasswordsAsync(ScanResult result)
    {
        try
        {
            // Try with sudo first, fall back to direct
            var output = await RunCommandAsync("sudo awk -F: '($2 == \"\") {print $1}' /etc/shadow 2>/dev/null");

            if (string.IsNullOrWhiteSpace(output))
            {
                // Try without sudo
                output = await RunCommandAsync("awk -F: '($2 == \"\") {print $1}' /etc/shadow 2>/dev/null");

                if (string.IsNullOrWhiteSpace(output) && !await CanReadShadowAsync())
                {
                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = "Permissions Issue",
                        Severity = "Low",
                        Description = "Cannot read /etc/shadow — password audit skipped. Run with sudo for full results.",
                        Remediation = "Run SecKit with sudo privileges for complete password auditing.",
                        Module = "UserAuditor",
                        Confidence = 100
                    });
                    return;
                }
            }

            if (string.IsNullOrWhiteSpace(output)) return;

            var users = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            foreach (var user in users)
            {
                var trimmed = user.Trim();
                if (string.IsNullOrWhiteSpace(trimmed)) continue;

                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "Empty Password",
                    Severity = "Critical",
                    Description = $"User '{trimmed}' has an empty password. Anyone can log in as this user without authentication.",
                    Remediation = $"Set a password: sudo passwd {trimmed}, or lock the account: sudo passwd -l {trimmed}",
                    Evidence = $"User: {trimmed}",
                    Module = "UserAuditor",
                    Confidence = 100
                });
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"Empty password check failed: {ex.Message}");
        }
    }

    /// <summary>Audits sudoers configuration for NOPASSWD and other risky directives.</summary>
    private static async Task AuditSudoersAsync(ScanResult result)
    {
        try
        {
            // Check main sudoers file and sudoers.d directory
            var output = await RunCommandAsync(
                "sudo grep -r 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null || " +
                "grep -r 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null");

            if (!string.IsNullOrWhiteSpace(output))
            {
                foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                {
                    var trimmed = line.Trim();
                    if (string.IsNullOrWhiteSpace(trimmed) || trimmed.StartsWith('#')) continue;

                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = "Sudo NOPASSWD",
                        Severity = "High",
                        Description = $"NOPASSWD sudo entry found: {trimmed}. Commands can be run as root without a password.",
                        Remediation = "Remove NOPASSWD from sudoers unless absolutely required. Use explicit command paths.",
                        Evidence = trimmed,
                        Module = "UserAuditor",
                        Confidence = 85
                    });
                }
            }

            // Check for ALL=(ALL) ALL access
            output = await RunCommandAsync(
                "sudo grep -rE '[^#]*ALL\\s*=\\s*\\(ALL\\)\\s*ALL' /etc/sudoers /etc/sudoers.d/ 2>/dev/null || " +
                "grep -rE '[^#]*ALL\\s*=\\s*\\(ALL\\)\\s*ALL' /etc/sudoers /etc/sudoers.d/ 2>/dev/null");

            if (!string.IsNullOrWhiteSpace(output))
            {
                foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                {
                    var trimmed = line.Trim();
                    if (string.IsNullOrWhiteSpace(trimmed) || trimmed.StartsWith('#')) continue;
                    // Skip the root entry
                    if (trimmed.StartsWith("root", StringComparison.OrdinalIgnoreCase)) continue;

                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = "Sudo Full Access",
                        Severity = "Medium",
                        Description = $"Unrestricted sudo access found: {trimmed}",
                        Remediation = "Restrict sudo access to specific commands only.",
                        Evidence = trimmed,
                        Module = "UserAuditor",
                        Confidence = 80
                    });
                }
            }

            // Check if sudoers.d/ files have insecure permissions
            if (Directory.Exists("/etc/sudoers.d"))
            {
                output = await RunCommandAsync(
                    "find /etc/sudoers.d -type f -perm /o+r,o+w,g+w 2>/dev/null");

                if (!string.IsNullOrWhiteSpace(output))
                {
                    foreach (var file in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                    {
                        result.Vulnerabilities.Add(new Vulnerability
                        {
                            Type = "Sudoers File Permissions",
                            Severity = "High",
                            Description = $"Sudoers file '{file.Trim()}' has insecure permissions.",
                            Remediation = $"Run: chmod 440 '{file.Trim()}'",
                            Evidence = file.Trim(),
                            Module = "UserAuditor",
                            Confidence = 90
                        });
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"Sudoers audit failed: {ex.Message}");
        }
    }

    /// <summary>Checks password aging for each user.</summary>
    private static async Task AuditPasswordAgingAsync(ScanResult result)
    {
        try
        {
            // Get list of users with login shells
            var usersOutput = await RunCommandAsync(
                "grep -E ':(/bin/bash|/bin/sh|/bin/zsh|/bin/fish)$' /etc/passwd | cut -d: -f1");

            if (string.IsNullOrWhiteSpace(usersOutput)) return;

            var users = usersOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries);

            foreach (var user in users)
            {
                var trimmed = user.Trim();
                if (string.IsNullOrWhiteSpace(trimmed)) continue;

                var chageOutput = await RunCommandAsync($"chage -l '{trimmed}' 2>/dev/null");
                if (string.IsNullOrWhiteSpace(chageOutput)) continue;

                // Parse chage output for password max days
                var maxDaysLine = chageOutput.Split('\n')
                    .FirstOrDefault(l => l.Contains("Maximum number of days", StringComparison.OrdinalIgnoreCase));

                if (maxDaysLine is not null)
                {
                    var maxDaysStr = maxDaysLine.Split(':').LastOrDefault()?.Trim();
                    if (int.TryParse(maxDaysStr, out var maxDays) && maxDays >= 99999)
                    {
                        result.Vulnerabilities.Add(new Vulnerability
                        {
                            Type = "Password Never Expires",
                            Severity = "Medium",
                            Description = $"User '{trimmed}' password never expires (max days: {maxDays}).",
                            Remediation = $"Run: sudo chage -M 90 '{trimmed}' to enforce password rotation every 90 days.",
                            Evidence = $"User: {trimmed} | Max days: {maxDays}",
                            Module = "UserAuditor",
                            Confidence = 85
                        });
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"Password aging audit failed: {ex.Message}");
        }
    }

    /// <summary>Checks for stale user accounts via lastlog.</summary>
    private static async Task AuditStaleAccountsAsync(ScanResult result)
    {
        try
        {
            // Use lastlog to find users who haven't logged in recently
            var output = await RunCommandAsync("lastlog 2>/dev/null | grep -v 'Never logged in' | tail -n +2");

            if (string.IsNullOrWhiteSpace(output)) return;

            foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var trimmed = line.Trim();
                if (string.IsNullOrWhiteSpace(trimmed)) continue;

                // If the line contains a date, parse it
                if (trimmed.Contains("**Never logged in**", StringComparison.OrdinalIgnoreCase))
                {
                    var user = trimmed.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
                    if (user is not null && user != "Username")
                    {
                        result.Vulnerabilities.Add(new Vulnerability
                        {
                            Type = "Stale Account",
                            Severity = "Medium",
                            Description = $"User '{user}' has never logged in. Consider removing or disabling the account.",
                            Remediation = $"Lock the account: sudo passwd -l {user}, or remove: sudo userdel {user}",
                            Evidence = $"User: {user} | Never logged in",
                            Module = "UserAuditor",
                            Confidence = 80
                        });
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"Stale account check failed: {ex.Message}");
        }
    }

    /// <summary>Checks for users in sensitive groups.</summary>
    private static async Task AuditSensitiveGroupMembershipsAsync(ScanResult result)
    {
        try
        {
            foreach (var group in SensitiveGroups)
            {
                var output = await RunCommandAsync($"getent group '{group}' 2>/dev/null | cut -d: -f4");

                if (string.IsNullOrWhiteSpace(output)) continue;

                var members = output.Trim().Split(',', StringSplitOptions.RemoveEmptyEntries);
                if (members.Length == 0) continue;

                foreach (var member in members)
                {
                    var trimmed = member.Trim();
                    if (string.IsNullOrWhiteSpace(trimmed)) continue;

                    var severity = group switch
                    {
                        "sudo" or "wheel" or "docker" => "Medium",
                        "shadow" or "disk" => "High",
                        _ => "Low"
                    };

                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = "Sensitive Group Membership",
                        Severity = severity,
                        Description = $"User '{trimmed}' is a member of the '{group}' group, which grants elevated privileges.",
                        Remediation = $"Review if {trimmed} needs {group} access. Remove with: sudo gpasswd -d {trimmed} {group}",
                        Evidence = $"User: {trimmed} | Group: {group}",
                        Module = "UserAuditor",
                        Confidence = 80
                    });
                }
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"Sensitive group audit failed: {ex.Message}");
        }
    }

    /// <summary>Checks if /etc/shadow is readable by the current process.</summary>
    private static async Task<bool> CanReadShadowAsync()
    {
        try
        {
            var output = await RunCommandAsync("test -r /etc/shadow && echo 'YES' || echo 'NO'");
            return output.Trim() == "YES";
        }
        catch
        {
            return false;
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
