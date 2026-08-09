using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecKit.Core;
using SecKit.Models;

namespace SecKit.Modules.Defense;

/// <summary>
/// Collects forensic artifacts from the system for incident response.
/// Gathers process lists, network connections, login history, shell history,
/// browser artifacts, recently modified files, system logs, USB history,
/// and installed packages into a structured forensic report.
/// All operations are read-only with minimal system impact.
/// </summary>
public class ForensicsCollector
{
    /// <summary>Default constructor.</summary>
    public ForensicsCollector() { }

    /// <summary>Constructor with configuration.</summary>
    public ForensicsCollector(ConfigManager config) { }

    // Common browser data directories
    private static readonly (string Browser, string[] Paths)[] BrowserProfiles =
    {
        ("Chrome",    new[] { "/home/*/.config/google-chrome", "/home/*/.config/chromium", "/root/.config/google-chrome" }),
        ("Firefox",   new[] { "/home/*/.mozilla/firefox", "/root/.mozilla/firefox" }),
        ("Brave",     new[] { "/home/*/.config/BraveSoftware/Brave-Browser" }),
        ("Edge",      new[] { "/home/*/.config/microsoft-edge" }),
        ("Opera",     new[] { "/home/*/.config/opera" }),
    };

    private static readonly string[] SystemLogPaths =
    {
        "/var/log/syslog", "/var/log/auth.log", "/var/log/kern.log",
        "/var/log/dmesg", "/var/log/dpkg.log", "/var/log/apt/history.log",
        "/var/log/secure", "/var/log/messages", "/var/log/boot.log",
        "/var/log/cron", "/var/log/audit/audit.log",
    };

    /// <summary>
    /// Runs a comprehensive forensic collection on the target system.
    /// </summary>
    /// <param name="target">Target specification — typically "localhost" or hostname.</param>
    /// <returns>ScanResult containing all collected forensic artifacts.</returns>
    public async Task<ScanResult> ScanAsync(string target = "")
    {
        var result = new ScanResult
        {
            ModuleName = "Forensics Collector",
            TargetUrl = string.IsNullOrWhiteSpace(target) ? Environment.MachineName : target,
            StartTime = DateTime.UtcNow
        };

        try
        {
            Logger.Info("Starting forensic data collection...");

            await Task.WhenAll(
                CollectProcessesAsync(result),
                CollectNetworkConnectionsAsync(result),
                CollectLoginHistoryAsync(result),
                CollectShellHistoryAsync(result),
                CollectBrowserArtifactsAsync(result),
                CollectRecentFilesAsync(result),
                CollectSystemLogsAsync(result),
                CollectUsbHistoryAsync(result),
                CollectInstalledPackagesAsync(result)
            );

            result.Completed = true;
            Logger.Info($"Forensics collection complete: {result.Vulnerabilities.Count} findings.");
        }
        catch (Exception ex)
        {
            result.ErrorMessage = ex.Message;
            Logger.Error($"Forensics collection failed: {ex.Message}");
        }

        result.EndTime = DateTime.UtcNow;
        return result;
    }

    /// <summary>Collects running processes (ps aux).</summary>
    private static async Task CollectProcessesAsync(ScanResult result)
    {
        try
        {
            var output = await RunCommandAsync("ps aux --no-headers 2>/dev/null | head -200");
            if (string.IsNullOrWhiteSpace(output)) return;

            var processes = new List<JsonObject>();
            foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var parts = line.Trim().Split(new[] { ' ' }, 11, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 11) continue;
                processes.Add(new JsonObject
                {
                    ["user"] = parts[0], ["pid"] = parts[1], ["cpu"] = parts[2],
                    ["mem"] = parts[3], ["vsz"] = parts[4], ["rss"] = parts[5],
                    ["tty"] = parts[6], ["stat"] = parts[7], ["start"] = parts[8],
                    ["time"] = parts[9], ["command"] = parts[10],
                });
            }

            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "Forensic: Running Processes",
                Severity = "Info",
                Description = $"Collected {processes.Count} running processes with command lines.",
                Remediation = "Review processes for suspicious or unexpected entries.",
                Evidence = JsonSerializer.Serialize(processes),
                Module = "ForensicsCollector",
                Confidence = 95
            });
        }
        catch (Exception ex) { Logger.Debug($"Process collection failed: {ex.Message}"); }
    }

    /// <summary>Collects network connections (ss -tlnp, ss -tunap).</summary>
    private static async Task CollectNetworkConnectionsAsync(ScanResult result)
    {
        try
        {
            var listenOutput = await RunCommandAsync("ss -tlnp 2>/dev/null | tail -n +2");
            var allOutput = await RunCommandAsync("ss -tunap 2>/dev/null | tail -n +2 | head -200");

            var listening = string.IsNullOrWhiteSpace(listenOutput) ? new List<JsonObject>()
                : listenOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries)
                    .Select(l => ParseSsLine(l.Trim()))
                    .Where(o => o != null).Cast<JsonObject>().ToList();

            var allConnections = string.IsNullOrWhiteSpace(allOutput) ? new List<JsonObject>()
                : allOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries)
                    .Select(l => ParseSsLine(l.Trim()))
                    .Where(o => o != null).Cast<JsonObject>().ToList();

            var suspiciousPorts = new Dictionary<int, string>
            {
                { 4444, "Common Meterpreter port" },
                { 1337, "Common backdoor port" },
                { 31337, "Back Orifice / Elite backdoor" },
                { 6667, "IRC (C2)" },
                { 9050, "Tor SOCKS" },
            };

            foreach (var conn in allConnections)
            {
                if (conn.TryGetPropertyValue("localPort", out var lpNode) &&
                    int.TryParse(lpNode?.ToString(), out var port) &&
                    suspiciousPorts.TryGetValue(port, out var reason))
                {
                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = "Suspicious Network Connection",
                        Severity = "High",
                        Description = $"Suspicious port {port} detected: {reason}.",
                        Remediation = "Investigate the process using this port.",
                        Evidence = JsonSerializer.Serialize(conn),
                        Module = "ForensicsCollector",
                        Confidence = 60
                    });
                }
            }

            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "Forensic: Network Connections",
                Severity = "Info",
                Description = $"Collected {listening.Count} listening sockets and {allConnections.Count} total connections.",
                Remediation = "Review for unauthorized services or suspicious outbound connections.",
                Evidence = JsonSerializer.Serialize(new { listening, all = allConnections }),
                Module = "ForensicsCollector",
                Confidence = 95
            });
        }
        catch (Exception ex) { Logger.Debug($"Network collection failed: {ex.Message}"); }
    }

    /// <summary>Collects login history (last, lastlog, w, who, whoami).</summary>
    private static async Task CollectLoginHistoryAsync(ScanResult result)
    {
        try
        {
            var lastOutput = await RunCommandAsync("last -n 100 2>/dev/null");
            var whoOutput = await RunCommandAsync("w -i 2>/dev/null");
            var whoAmI = await RunCommandAsync("whoami 2>/dev/null");

            var logins = new JsonObject
            {
                ["currentUser"] = whoAmI?.Trim(),
                ["whoDetails"] = whoOutput?.Trim(),
                ["recentLogins"] = lastOutput?.Trim(),
            };

            if (!string.IsNullOrWhiteSpace(lastOutput))
            {
                var rootLogins = lastOutput.Split('\n')
                    .Where(l => l.Contains("root") && !l.Contains(":0") && !l.Contains("tty") && l.Trim().Length > 0)
                    .Take(5).ToList();
                if (rootLogins.Count > 0)
                {
                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = "Remote Root Logins",
                        Severity = "High",
                        Description = $"Found {rootLogins.Count} remote root login entries. Direct root SSH should be disabled.",
                        Remediation = "Set 'PermitRootLogin no' in /etc/ssh/sshd_config.",
                        Evidence = string.Join("\n", rootLogins),
                        Module = "ForensicsCollector",
                        Confidence = 85
                    });
                }
            }

            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "Forensic: Login History",
                Severity = "Info",
                Description = "Collected login history and current sessions.",
                Remediation = "Review for unauthorized access.",
                Evidence = JsonSerializer.Serialize(logins),
                Module = "ForensicsCollector",
                Confidence = 95
            });
        }
        catch (Exception ex) { Logger.Debug($"Login history failed: {ex.Message}"); }
    }

    /// <summary>Collects shell history (.bash_history, .zsh_history).</summary>
    private static async Task CollectShellHistoryAsync(ScanResult result)
    {
        try
        {
            var histories = new JsonObject();
            var findOutput = await RunCommandAsync(
                "find /home /root -maxdepth 3 \\( -name '.bash_history' -o -name '.zsh_history' " +
                "-o -name '.mysql_history' -o -name '.python_history' \\) -type f 2>/dev/null");

            if (!string.IsNullOrWhiteSpace(findOutput))
            {
                var historyFiles = findOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                foreach (var hf in historyFiles)
                {
                    var trimmed = hf.Trim();
                    if (string.IsNullOrWhiteSpace(trimmed) || !File.Exists(trimmed)) continue;
                    try
                    {
                        var lines = await File.ReadAllLinesAsync(trimmed);
                        var tail = lines.Length > 100 ? lines[^100..] : lines;
                        var safeName = trimmed.Replace('/', '_').TrimStart('_');

                        var suspiciousPatterns = new[]
                        {
                            "wget", "curl", "nc ", "netcat", "bash -i", "python -c",
                            "chmod +s", "chmod 4777", "rm -rf", "dd if=",
                            "/dev/tcp", "exec", "base64 -d", "openssl enc",
                            "nohup", "disown", "shred", "wipe",
                        };

                        foreach (var line in tail)
                        {
                            if (string.IsNullOrWhiteSpace(line)) continue;
                            foreach (var pattern in suspiciousPatterns)
                            {
                                if (line.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                                {
                                    result.Vulnerabilities.Add(new Vulnerability
                                    {
                                        Type = "Suspicious Shell Command",
                                        Severity = "Medium",
                                        Description = $"Suspicious command in {trimmed}: '{line.Trim()}'",
                                        Remediation = "Review this command and verify authorization.",
                                        Evidence = $"File: {trimmed} | Command: {line.Trim()}",
                                        Module = "ForensicsCollector",
                                        Confidence = 60
                                    });
                                    break;
                                }
                            }
                        }
                        histories[safeName] = string.Join("\n", tail);
                    }
                    catch (Exception ex)
                    {
                        Logger.Debug($"Could not read {trimmed}: {ex.Message}");
                        histories[trimmed] = $"[Error: {ex.Message}]";
                    }
                }
            }

            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "Forensic: Shell History",
                Severity = "Info",
                Description = $"Collected shell history from {histories.Count} files.",
                Remediation = "Review for unauthorized commands.",
                Evidence = JsonSerializer.Serialize(histories),
                Module = "ForensicsCollector",
                Confidence = 90
            });
        }
        catch (Exception ex) { Logger.Debug($"Shell history failed: {ex.Message}"); }
    }

    /// <summary>Collects browser artifacts via SQLite parsing.</summary>
    private static async Task CollectBrowserArtifactsAsync(ScanResult result)
    {
        try
        {
            var browserData = new JsonObject();
            foreach (var (browser, patterns) in BrowserProfiles)
            {
                var browserSection = new JsonObject();
                foreach (var pattern in patterns)
                {
                    var expanded = await RunCommandAsync(
                        $"for d in {pattern} 2>/dev/null; do [ -d \"$d\" ] && echo \"$d\"; done");
                    if (string.IsNullOrWhiteSpace(expanded)) continue;

                    foreach (var profileDir in expanded.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                    {
                        var trimmed = profileDir.Trim();
                        if (string.IsNullOrWhiteSpace(trimmed)) continue;
                        var profileSection = new JsonObject();

                        if (browser == "Chrome" || browser == "Brave" || browser == "Edge" || browser == "Opera")
                        {
                            var historyDb = Path.Combine(trimmed, "Default", "History");
                            if (!File.Exists(historyDb)) historyDb = Path.Combine(trimmed, "History");
                            if (File.Exists(historyDb))
                            {
                                try { profileSection["history"] = await ParseChromeHistoryAsync(historyDb); }
                                catch (Exception ex) { profileSection["historyError"] = ex.Message; }
                            }

                            var cookiesDb = Path.Combine(trimmed, "Default", "Cookies");
                            if (!File.Exists(cookiesDb)) cookiesDb = Path.Combine(trimmed, "Cookies");
                            if (File.Exists(cookiesDb))
                            {
                                try { profileSection["cookies"] = await ParseChromeCookiesAsync(cookiesDb); }
                                catch (Exception ex) { profileSection["cookiesError"] = ex.Message; }
                            }

                            var downloadsDb = Path.Combine(trimmed, "Default", "History");
                            if (File.Exists(downloadsDb))
                            {
                                try { profileSection["downloads"] = await ParseChromeDownloadsAsync(downloadsDb); }
                                catch (Exception ex) { profileSection["downloadsError"] = ex.Message; }
                            }
                        }
                        else if (browser == "Firefox")
                        {
                            var escapedDir = trimmed.Replace("'", "'\\''");
                            var placesDb = (await RunCommandAsync(
                                $"find '{escapedDir}' -name 'places.sqlite' -type f 2>/dev/null | head -1"))?.Trim();
                            if (!string.IsNullOrWhiteSpace(placesDb) && File.Exists(placesDb))
                            {
                                try { profileSection["history"] = await ParseFirefoxHistoryAsync(placesDb); }
                                catch (Exception ex) { profileSection["historyError"] = ex.Message; }
                            }

                            var cookiesDb = (await RunCommandAsync(
                                $"find '{escapedDir}' -name 'cookies.sqlite' -type f 2>/dev/null | head -1"))?.Trim();
                            if (!string.IsNullOrWhiteSpace(cookiesDb) && File.Exists(cookiesDb))
                            {
                                try { profileSection["cookies"] = await ParseFirefoxCookiesAsync(cookiesDb); }
                                catch (Exception ex) { profileSection["cookiesError"] = ex.Message; }
                            }
                        }

                        profileSection["path"] = trimmed;
                        profileSection["exists"] = Directory.Exists(trimmed);
                        browserSection[Path.GetFileName(trimmed)] = profileSection;
                    }
                }
                if (browserSection.Count > 0) browserData[browser] = browserSection;
            }

            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "Forensic: Browser Artifacts",
                Severity = "Info",
                Description = $"Collected browser artifacts from {browserData.Count} browser(s).",
                Remediation = "Review browser history for data exfiltration indicators.",
                Evidence = JsonSerializer.Serialize(browserData),
                Module = "ForensicsCollector",
                Confidence = 80
            });
        }
        catch (Exception ex) { Logger.Debug($"Browser artifacts failed: {ex.Message}"); }
    }

    /// <summary>Collects recently modified files (find -mtime -7).</summary>
    private static async Task CollectRecentFilesAsync(ScanResult result)
    {
        try
        {
            var homeOutput = await RunCommandAsync(
                "find /home /root /tmp /var/tmp -maxdepth 4 -mtime -7 -type f 2>/dev/null | head -200");
            var etcOutput = await RunCommandAsync(
                "find /etc -maxdepth 2 -mtime -7 -type f 2>/dev/null | head -50");
            var recentFiles = new List<JsonObject>();

            void ParseOutput(string output, string category)
            {
                if (string.IsNullOrWhiteSpace(output)) return;
                foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                {
                    var file = line.Trim();
                    if (string.IsNullOrWhiteSpace(file)) continue;
                    try
                    {
                        var fi = new FileInfo(file);
                        recentFiles.Add(new JsonObject
                        {
                            ["path"] = file, ["size"] = fi.Length,
                            ["modified"] = fi.LastWriteTimeUtc.ToString("O"), ["category"] = category,
                        });
                    }
                    catch
                    {
                        recentFiles.Add(new JsonObject { ["path"] = file, ["category"] = category });
                    }
                }
            }

            ParseOutput(homeOutput, "home");
            ParseOutput(etcOutput, "etc");

            foreach (var rf in recentFiles)
            {
                var path = (rf["path"]?.ToString() ?? "").ToLowerInvariant();
                if (path.EndsWith(".php") || path.EndsWith(".jsp") || path.EndsWith(".asp"))
                {
                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = "Recently Modified Web Shell",
                        Severity = "High",
                        Description = $"Recently modified web-accessible file: '{rf["path"]}'. Could be a web shell.",
                        Remediation = "Verify the file is legitimate.",
                        Evidence = $"Path: {rf["path"]} | Modified: {rf["modified"]}",
                        Module = "ForensicsCollector",
                        Confidence = 50
                    });
                }
            }

            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "Forensic: Recently Modified Files",
                Severity = "Info",
                Description = $"Collected {recentFiles.Count} recently modified files (last 7 days).",
                Remediation = "Review for unauthorized modifications.",
                Evidence = JsonSerializer.Serialize(recentFiles),
                Module = "ForensicsCollector",
                Confidence = 90
            });
        }
        catch (Exception ex) { Logger.Debug($"Recent files failed: {ex.Message}"); }
    }

    /// <summary>Collects system logs (last 200 lines each).</summary>
    private static async Task CollectSystemLogsAsync(ScanResult result)
    {
        try
        {
            var logs = new JsonObject();
            var collected = 0;
            foreach (var logPath in SystemLogPaths)
            {
                if (!File.Exists(logPath)) continue;
                try
                {
                    var output = await RunCommandAsync($"tail -n 200 '{logPath.Replace("'", "'\\''")}' 2>/dev/null");
                    if (string.IsNullOrWhiteSpace(output)) continue;
                    logs[Path.GetFileName(logPath)] = output;
                    collected++;
                }
                catch { }
            }

            var journalOutput = await RunCommandAsync("journalctl -n 50 --no-pager 2>/dev/null");
            if (!string.IsNullOrWhiteSpace(journalOutput)) { logs["journalctl"] = journalOutput; collected++; }

            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "Forensic: System Logs",
                Severity = "Info",
                Description = $"Collected {collected} system log files.",
                Remediation = "Review logs for authentication failures and suspicious activity.",
                Evidence = JsonSerializer.Serialize(logs),
                Module = "ForensicsCollector",
                Confidence = 90
            });
        }
        catch (Exception ex) { Logger.Debug($"System logs failed: {ex.Message}"); }
    }

    /// <summary>Collects USB device history from dmesg and lsusb.</summary>
    private static async Task CollectUsbHistoryAsync(ScanResult result)
    {
        try
        {
            var dmesgOutput = await RunCommandAsync("dmesg 2>/dev/null | grep -i usb | tail -n 50");
            var lsusbOutput = await RunCommandAsync("lsusb 2>/dev/null");

            var usbData = new JsonObject
            {
                ["dmesg_usb"] = dmesgOutput?.Trim() ?? "",
                ["lsusb"] = lsusbOutput?.Trim() ?? "",
            };

            if (!string.IsNullOrWhiteSpace(dmesgOutput) &&
                dmesgOutput.Contains("Mass Storage", StringComparison.OrdinalIgnoreCase))
            {
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "USB Mass Storage Detected",
                    Severity = "Medium",
                    Description = "USB mass storage devices have been connected. Check for unauthorized data transfer.",
                    Remediation = "Review USB connection history. Implement USB device control policies.",
                    Evidence = dmesgOutput.Split('\n').FirstOrDefault(l =>
                        l.Contains("Mass Storage", StringComparison.OrdinalIgnoreCase)) ?? "USB storage found",
                    Module = "ForensicsCollector",
                    Confidence = 70
                });
            }

            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "Forensic: USB Device History",
                Severity = "Info",
                Description = "Collected USB device connection history.",
                Remediation = "Verify all USB devices were authorized.",
                Evidence = JsonSerializer.Serialize(usbData),
                Module = "ForensicsCollector",
                Confidence = 90
            });
        }
        catch (Exception ex) { Logger.Debug($"USB history failed: {ex.Message}"); }
    }

    /// <summary>Collects installed packages (dpkg, rpm, snap, pip, npm).</summary>
    private static async Task CollectInstalledPackagesAsync(ScanResult result)
    {
        try
        {
            var packages = new JsonObject();
            var dpkgOutput = await RunCommandAsync("dpkg -l 2>/dev/null | tail -n +6 | head -500");
            var rpmOutput = await RunCommandAsync("rpm -qa --queryformat '%{NAME} %{VERSION}\\n' 2>/dev/null | head -500");
            var snapOutput = await RunCommandAsync("snap list 2>/dev/null");
            var pipOutput = await RunCommandAsync("pip3 list --format=columns 2>/dev/null | head -200");

            if (!string.IsNullOrWhiteSpace(dpkgOutput)) packages["dpkg"] = dpkgOutput;
            if (!string.IsNullOrWhiteSpace(rpmOutput)) packages["rpm"] = rpmOutput;
            if (!string.IsNullOrWhiteSpace(snapOutput)) packages["snap"] = snapOutput;
            if (!string.IsNullOrWhiteSpace(pipOutput)) packages["pip3"] = pipOutput;

            var suspiciousPkgs = new[] { "netcat", "ncat", "socat", "nmap", "tcpdump",
                "john", "hashcat", "hydra", "aircrack-ng", "metasploit",
                "beef", "sqlmap", "nikto", "dirb", "gobuster", "wfuzz" };

            if (!string.IsNullOrWhiteSpace(dpkgOutput))
            {
                foreach (var pkg in suspiciousPkgs)
                {
                    if (dpkgOutput.Contains($" {pkg} ", StringComparison.OrdinalIgnoreCase))
                    {
                        result.Vulnerabilities.Add(new Vulnerability
                        {
                            Type = "Suspicious Package Installed",
                            Severity = "Medium",
                            Description = $"Potentially offensive security tool '{pkg}' installed. Verify authorization.",
                            Remediation = $"Remove if unauthorized: sudo apt remove {pkg}",
                            Evidence = $"Package: {pkg}",
                            Module = "ForensicsCollector",
                            Confidence = 60
                        });
                    }
                }
            }

            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "Forensic: Installed Packages",
                Severity = "Info",
                Description = $"Collected installed packages from {packages.Count} package managers.",
                Remediation = "Review installed packages for unauthorized software.",
                Evidence = JsonSerializer.Serialize(packages),
                Module = "ForensicsCollector",
                Confidence = 95
            });
        }
        catch (Exception ex) { Logger.Debug($"Package collection failed: {ex.Message}"); }
    }

    // --- SQLite parsing helpers ---

    private static async Task<JsonObject> ParseChromeHistoryAsync(string dbPath)
    {
        var result = new JsonObject();
        try
        {
            var output = await RunCommandAsync(
                $"sqlite3 '{dbPath.Replace("'", "'\\''")}' " +
                "\"SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 50;\" 2>/dev/null");
            if (!string.IsNullOrWhiteSpace(output))
            {
                var entries = new List<JsonObject>();
                foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                {
                    var parts = line.Split('|');
                    if (parts.Length >= 4)
                    {
                        entries.Add(new JsonObject
                        {
                            ["url"] = parts[0], ["title"] = parts[1],
                            ["visitCount"] = parts[2], ["lastVisit"] = parts[3],
                        });
                    }
                }
                result["urls"] = JsonSerializer.Serialize(entries);
                result["totalEntries"] = entries.Count.ToString();
            }
        }
        catch (Exception ex) { result["error"] = ex.Message; }
        return result;
    }

    private static async Task<JsonObject> ParseChromeCookiesAsync(string dbPath)
    {
        var result = new JsonObject();
        try
        {
            var output = await RunCommandAsync(
                $"sqlite3 '{dbPath.Replace("'", "'\\''")}' " +
                "\"SELECT host_key, name, datetime(expires_utc/1000000-11644473600,'unixepoch') FROM cookies LIMIT 50;\" 2>/dev/null");
            if (!string.IsNullOrWhiteSpace(output))
            {
                var entries = new List<JsonObject>();
                foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                {
                    var parts = line.Split('|');
                    if (parts.Length >= 3)
                    {
                        entries.Add(new JsonObject
                        {
                            ["domain"] = parts[0], ["name"] = parts[1], ["expires"] = parts[2],
                        });
                    }
                }
                result["cookies"] = JsonSerializer.Serialize(entries);
                result["totalCookies"] = entries.Count.ToString();
            }
        }
        catch (Exception ex) { result["error"] = ex.Message; }
        return result;
    }

    private static async Task<JsonObject> ParseChromeDownloadsAsync(string dbPath)
    {
        var result = new JsonObject();
        try
        {
            var output = await RunCommandAsync(
                $"sqlite3 '{dbPath.Replace("'", "'\\''")}' " +
                "\"SELECT target_path, total_bytes, datetime(start_time/1000000-11644473600,'unixepoch') " +
                "FROM downloads ORDER BY start_time DESC LIMIT 20;\" 2>/dev/null");
            if (!string.IsNullOrWhiteSpace(output))
            {
                var entries = new List<JsonObject>();
                foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                {
                    var parts = line.Split('|');
                    if (parts.Length >= 3)
                    {
                        entries.Add(new JsonObject
                        {
                            ["path"] = parts[0], ["size"] = parts[1], ["date"] = parts[2],
                        });
                    }
                }
                result["downloads"] = JsonSerializer.Serialize(entries);
                result["totalDownloads"] = entries.Count.ToString();
            }
        }
        catch (Exception ex) { result["error"] = ex.Message; }
        return result;
    }

    private static async Task<JsonObject> ParseFirefoxHistoryAsync(string dbPath)
    {
        var result = new JsonObject();
        try
        {
            var output = await RunCommandAsync(
                $"sqlite3 '{dbPath.Replace("'", "'\\''")}' " +
                "\"SELECT moz_places.url, moz_places.title, moz_places.visit_count, " +
                "datetime(moz_historyvisits.visit_date/1000000,'unixepoch') " +
                "FROM moz_places JOIN moz_historyvisits ON moz_places.id = moz_historyvisits.place_id " +
                "ORDER BY moz_historyvisits.visit_date DESC LIMIT 50;\" 2>/dev/null");
            if (!string.IsNullOrWhiteSpace(output))
            {
                var entries = new List<JsonObject>();
                foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                {
                    var parts = line.Split('|');
                    if (parts.Length >= 4)
                    {
                        entries.Add(new JsonObject
                        {
                            ["url"] = parts[0], ["title"] = parts[1],
                            ["visitCount"] = parts[2], ["lastVisit"] = parts[3],
                        });
                    }
                }
                result["urls"] = JsonSerializer.Serialize(entries);
                result["totalEntries"] = entries.Count.ToString();
            }
        }
        catch (Exception ex) { result["error"] = ex.Message; }
        return result;
    }

    private static async Task<JsonObject> ParseFirefoxCookiesAsync(string dbPath)
    {
        var result = new JsonObject();
        try
        {
            var output = await RunCommandAsync(
                $"sqlite3 '{dbPath.Replace("'", "'\\''")}' " +
                "\"SELECT host, name, datetime(expiry,'unixepoch') FROM moz_cookies LIMIT 50;\" 2>/dev/null");
            if (!string.IsNullOrWhiteSpace(output))
            {
                var entries = new List<JsonObject>();
                foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                {
                    var parts = line.Split('|');
                    if (parts.Length >= 3)
                    {
                        entries.Add(new JsonObject
                        {
                            ["domain"] = parts[0], ["name"] = parts[1], ["expires"] = parts[2],
                        });
                    }
                }
                result["cookies"] = JsonSerializer.Serialize(entries);
                result["totalCookies"] = entries.Count.ToString();
            }
        }
        catch (Exception ex) { result["error"] = ex.Message; }
        return result;
    }

    /// <summary>Parses a single line of ss output into a JSON object.</summary>
    private static JsonObject? ParseSsLine(string line)
    {
        try
        {
            var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 4) return null;
            var obj = new JsonObject { ["protocol"] = parts[0] };

            var local = parts.Length > 4 ? parts[4] : parts[3];
            var lastColon = local.LastIndexOf(':');
            obj["localAddress"] = lastColon > 0 ? local[..lastColon] : local;
            obj["localPort"] = lastColon > 0 ? local[(lastColon + 1)..] : "";

            if (parts.Length > 5)
            {
                var peer = parts[5];
                lastColon = peer.LastIndexOf(':');
                obj["peerAddress"] = (lastColon > 0 ? peer[..lastColon] : peer).TrimStart('[').TrimEnd(']');
                obj["peerPort"] = lastColon > 0 ? peer[(lastColon + 1)..] : "";
            }

            if (parts.Length > 1) obj["state"] = parts[1];

            for (int i = 0; i < parts.Length; i++)
            {
                if (parts[i].Contains("users:("))
                {
                    obj["process"] = parts[i].Replace("users:(", "").Replace("))", "").Replace(")", "").Trim('"');
                    break;
                }
            }
            return obj;
        }
        catch { return null; }
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
