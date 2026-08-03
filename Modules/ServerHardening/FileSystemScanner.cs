using System.Diagnostics;
using SecKit.Core;
using SecKit.Models;

namespace SecKit.Modules.ServerHardening;

/// <summary>
/// Scans the filesystem for common security issues: world-writable files,
/// SUID/SGID binaries, exposed secrets, insecure /tmp permissions,
/// and writable web roots.
/// </summary>
public class FileSystemScanner
{
    // Directories to check for exposed secrets
    private static readonly string[] WebRoots =
    {
        "/var/www", "/var/www/html", "/srv", "/opt",
        "/home", "/usr/share/nginx", "/usr/local/www"
    };

    // Common directories to limit find scope (avoid scanning entire filesystem)
    private static readonly string[] ScanDirs =
    {
        "/etc", "/var", "/opt", "/srv", "/home", "/root", "/usr/local/bin", "/usr/local/sbin"
    };

    /// <summary>
    /// Scans the filesystem on the target for security misconfigurations.
    /// </summary>
    /// <param name="target">Target hostname or IP (typically localhost).</param>
    /// <returns>ScanResult with filesystem security findings.</returns>
    public async Task<ScanResult> ScanAsync(string target)
    {
        var result = new ScanResult
        {
            ModuleName = "File System Scanner",
            TargetUrl = target,
            StartTime = DateTime.UtcNow
        };

        try
        {
            Logger.Info("Scanning filesystem for security issues...");

            // Run all checks in parallel for performance
            var tasks = new[]
            {
                ScanWorldWritableFilesAsync(result),
                ScanSuidSgidBinariesAsync(result),
                ScanExposedSecretsAsync(result),
                CheckTmpPermissionsAsync(result),
                ScanWritableWebRootsAsync(result)
            };

            await Task.WhenAll(tasks);

            result.Completed = true;
            Logger.Info($"Filesystem scan complete: {result.Vulnerabilities.Count} findings.");
        }
        catch (Exception ex)
        {
            result.ErrorMessage = ex.Message;
            Logger.Error($"Filesystem scanner failed: {ex.Message}");
        }

        result.EndTime = DateTime.UtcNow;
        return result;
    }

    /// <summary>Finds world-writable files in common directories.</summary>
    private static async Task ScanWorldWritableFilesAsync(ScanResult result)
    {
        try
        {
            var dirs = string.Join(" ", ScanDirs.Where(Directory.Exists));
            if (string.IsNullOrWhiteSpace(dirs))
            {
                Logger.Debug("No scan directories exist for world-writable check.");
                return;
            }

            var output = await RunCommandAsync(
                $"find {dirs} -perm -o+w -type f 2>/dev/null | head -50");

            if (string.IsNullOrWhiteSpace(output)) return;

            var files = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            if (files.Length > 0)
            {
                // Cap at 15 individual findings to avoid flooding
                var count = Math.Min(files.Length, 15);
                for (int i = 0; i < count; i++)
                {
                    var file = files[i].Trim();
                    if (string.IsNullOrWhiteSpace(file)) continue;

                    var severity = file.StartsWith("/etc/") || file.StartsWith("/root/") ? "High" : "Medium";

                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = "World-Writable File",
                        Severity = severity,
                        Description = $"File '{file}' is world-writable, allowing any user to modify its contents.",
                        Remediation = $"Run: chmod o-w '{file}' to remove world write permission.",
                        Evidence = file,
                        Module = "FileSystemScanner",
                        Confidence = 90
                    });
                }

                if (files.Length > 15)
                {
                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = "World-Writable Files",
                        Severity = "Info",
                        Description = $"Found {files.Length} world-writable files total (showing first 15).",
                        Remediation = "Review and restrict permissions on world-writable files.",
                        Evidence = $"Count: {files.Length}",
                        Module = "FileSystemScanner",
                        Confidence = 85
                    });
                }
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"World-writable scan failed: {ex.Message}");
        }
    }

    /// <summary>Finds SUID/SGID binaries that could be exploited for privilege escalation.</summary>
    private static async Task ScanSuidSgidBinariesAsync(ScanResult result)
    {
        try
        {
            var output = await RunCommandAsync(
                "find / -perm -4000 -o -perm -2000 -type f 2>/dev/null | head -100");

            if (string.IsNullOrWhiteSpace(output)) return;

            var binaries = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);

            // Known-dangerous SUID binaries (GTFOBins common targets)
            var dangerousPatterns = new[]
            {
                "vim", "nano", "emacs", "less", "more", "find", "bash", "sh", "zsh",
                "python", "perl", "ruby", "php", "awk", "sed", "tar", "zip", "unzip",
                "systemctl", "journalctl", "docker", "pkexec", "crontab", "ping",
                "mount", "umount", "su", "sudo", "passwd", "chsh", "chfn", "newgrp",
                "gdb", "strace", "nmap", "tcpdump", "wireshark", "dumpcap",
                "screen", "tmux", "script", "expect"
            };

            foreach (var binary in binaries)
            {
                var trimmed = binary.Trim();
                if (string.IsNullOrWhiteSpace(trimmed)) continue;

                var name = Path.GetFileName(trimmed);
                var isDangerous = dangerousPatterns.Any(p =>
                    name.Equals(p, StringComparison.OrdinalIgnoreCase) ||
                    name.StartsWith(p, StringComparison.OrdinalIgnoreCase));

                if (isDangerous)
                {
                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = "Suspicious SUID/SGID Binary",
                        Severity = "High",
                        Description = $"SUID/SGID binary '{trimmed}' could be exploited for privilege escalation.",
                        Remediation = $"Remove SUID bit if not needed: chmod -s '{trimmed}'",
                        Evidence = trimmed,
                        Module = "FileSystemScanner",
                        Confidence = 70
                    });
                }
            }

            // Summary of total count
            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "SUID/SGID Binaries",
                Severity = "Info",
                Description = $"Found {binaries.Length} SUID/SGID binaries on the system.",
                Remediation = "Review SUID/SGID binaries and remove unnecessary setuid/setgid bits.",
                Evidence = $"Count: {binaries.Length}",
                Module = "FileSystemScanner",
                Confidence = 90
            });
        }
        catch (Exception ex)
        {
            Logger.Debug($"SUID/SGID scan failed: {ex.Message}");
        }
    }

    /// <summary>Checks for exposed secrets and sensitive files in web-accessible locations.</summary>
    private static async Task ScanExposedSecretsAsync(ScanResult result)
    {
        try
        {
            var webRoots = string.Join(" ", WebRoots.Where(Directory.Exists));
            if (string.IsNullOrWhiteSpace(webRoots))
            {
                Logger.Debug("No web roots found for exposed secrets check.");
                return;
            }

            var patterns = "\\( -name \".env\" -o -name \".git\" -o -name \"*.pem\" " +
                           "-o -name \"id_rsa\" -o -name \"*_rsa\" -o -name \"id_ed25519\" " +
                           "-o -name \"backup*\" -o -name \"*.sql\" -o -name \"*.sql.gz\" " +
                           "-o -name \"*.dump\" -o -name \"credentials*\" -o -name \"*.key\" " +
                           "-o -name \"*.pfx\" -o -name \"*.p12\" -o -name \"config.php\" " +
                           "-o -name \"wp-config.php\" -o -name \"settings.py\" \\)";

            var output = await RunCommandAsync(
                $"find {webRoots} {patterns} -type f 2>/dev/null | head -50");

            if (string.IsNullOrWhiteSpace(output)) return;

            var files = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            foreach (var file in files)
            {
                var trimmed = file.Trim();
                if (string.IsNullOrWhiteSpace(trimmed)) continue;

                var severity = trimmed.EndsWith(".pem") || trimmed.EndsWith("id_rsa") ||
                              trimmed.EndsWith("_rsa") || trimmed.EndsWith(".key") ||
                              trimmed.Contains("credentials")
                    ? "Critical"
                    : "High";

                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "Exposed Sensitive File",
                    Severity = severity,
                    Description = $"Sensitive file '{trimmed}' may be accessible via the web server.",
                    Remediation = $"Move '{trimmed}' outside the web root, or configure the web server to deny access.",
                    Evidence = trimmed,
                    Module = "FileSystemScanner",
                    Confidence = 75
                });
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"Exposed secrets scan failed: {ex.Message}");
        }
    }

    /// <summary>Checks /tmp permissions (should be 1777 with sticky bit).</summary>
    private static async Task CheckTmpPermissionsAsync(ScanResult result)
    {
        try
        {
            var tmpDirs = new[] { "/tmp", "/var/tmp", "/dev/shm" };

            foreach (var dir in tmpDirs)
            {
                if (!Directory.Exists(dir)) continue;

                var output = await RunCommandAsync($"stat -c '%a %A' '{dir}' 2>/dev/null");
                if (string.IsNullOrWhiteSpace(output)) continue;

                var parts = output.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2) continue;

                var octalPerms = parts[0];
                var humanPerms = parts[1];

                // Check for sticky bit (first digit should be 1 for sticky)
                var isSticky = octalPerms.Length >= 4 && octalPerms[0] == '1';
                var isWorldWritable = octalPerms.Length >= 3 && octalPerms[octalPerms.Length - 3] >= '7';
                var noExec = humanPerms.Contains("noexec");

                if (!isSticky)
                {
                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = "Directory Permissions",
                        Severity = "Medium",
                        Description = $"{dir} is missing the sticky bit. Without it, users can delete files owned by others.",
                        Remediation = $"Run: chmod +t '{dir}'",
                        Evidence = $"Perms: {octalPerms}",
                        Module = "FileSystemScanner",
                        Confidence = 85
                    });
                }

                if (!isWorldWritable && dir == "/tmp")
                {
                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = "Directory Permissions",
                        Severity = "Low",
                        Description = $"{dir} is not world-writable which may break applications, but is more secure.",
                        Remediation = $"If needed, run: chmod 1777 '{dir}'",
                        Evidence = $"Perms: {octalPerms}",
                        Module = "FileSystemScanner",
                        Confidence = 70
                    });
                }

                // /dev/shm is a known attack vector
                if (dir == "/dev/shm" && !noExec)
                {
                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = "Shared Memory Mount",
                        Severity = "Medium",
                        Description = "/dev/shm is mounted without noexec. This is a common staging area for exploits.",
                        Remediation = "Add 'noexec' to the /dev/shm mount options in /etc/fstab.",
                        Evidence = $"Mount options missing noexec",
                        Module = "FileSystemScanner",
                        Confidence = 75
                    });
                }
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"Tmp permissions check failed: {ex.Message}");
        }
    }

    /// <summary>Checks if common web root directories are writable by the web server user.</summary>
    private static async Task ScanWritableWebRootsAsync(ScanResult result)
    {
        try
        {
            foreach (var dir in WebRoots)
            {
                if (!Directory.Exists(dir)) continue;

                var output = await RunCommandAsync(
                    $"find '{dir}' -maxdepth 2 -type d -perm -o+w 2>/dev/null | head -20");

                if (string.IsNullOrWhiteSpace(output)) continue;

                var dirs = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                foreach (var writableDir in dirs)
                {
                    var trimmed = writableDir.Trim();
                    if (string.IsNullOrWhiteSpace(trimmed)) continue;

                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = "Writable Web Directory",
                        Severity = "Medium",
                        Description = $"Web directory '{trimmed}' is world-writable, potentially allowing file upload or modification by attackers.",
                        Remediation = $"Restrict write permissions: chmod o-w '{trimmed}'. If the web server needs write access, use group permissions instead.",
                        Evidence = trimmed,
                        Module = "FileSystemScanner",
                        Confidence = 80
                    });
                }
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"Writable web roots scan failed: {ex.Message}");
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
