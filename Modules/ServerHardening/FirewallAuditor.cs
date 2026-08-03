using System.Diagnostics;
using SecKit.Core;
using SecKit.Models;

namespace SecKit.Modules.ServerHardening;

/// <summary>
/// Audits firewall configuration (iptables and nftables) for security issues:
/// default policies, missing rules, exposed sensitive ports, missing rate limiting,
/// and overly permissive rulesets.
/// </summary>
public class FirewallAuditor
{
    // Sensitive ports that should never be exposed to public interfaces
    private static readonly Dictionary<int, string> SensitivePorts = new()
    {
        { 22, "SSH" },
        { 3306, "MySQL/MariaDB" },
        { 5432, "PostgreSQL" },
        { 6379, "Redis" },
        { 27017, "MongoDB" },
        { 9200, "Elasticsearch" },
        { 9300, "Elasticsearch (transport)" },
        { 11211, "Memcached" },
        { 2375, "Docker (unencrypted)" },
        { 2376, "Docker (TLS)" },
        { 6443, "Kubernetes API" },
        { 10250, "Kubelet API" },
        { 10255, "Kubelet (read-only)" },
        { 5000, "Docker Registry" },
        { 3389, "RDP" },
        { 5900, "VNC" },
        { 5901, "VNC" },
        { 53, "DNS" },
        { 161, "SNMP" },
        { 389, "LDAP" },
        { 636, "LDAPS" },
        { 1433, "MSSQL" },
        { 1521, "Oracle DB" },
        { 2049, "NFS" },
        { 9090, "Prometheus" },
        { 3000, "Grafana" },
        { 8080, "HTTP-Alt (Jenkins, etc.)" },
        { 8443, "HTTPS-Alt" },
        { 5001, "Synology DSM" },
    };

    /// <summary>
    /// Audits the firewall configuration (iptables/nftables) on the target system.
    /// </summary>
    /// <param name="target">Target hostname or IP (typically localhost).</param>
    /// <returns>ScanResult with firewall audit findings.</returns>
    public async Task<ScanResult> ScanAsync(string target)
    {
        var result = new ScanResult
        {
            ModuleName = "Firewall Auditor",
            TargetUrl = target,
            StartTime = DateTime.UtcNow
        };

        try
        {
            Logger.Info("Auditing firewall configuration...");

            // Check which firewall is in use
            var nftCheck = await RunCommandAsync("which nft 2>/dev/null");
            var iptCheck = await RunCommandAsync("which iptables 2>/dev/null");

            var firewallFound = false;

            if (!string.IsNullOrWhiteSpace(nftCheck))
            {
                Logger.Debug("nftables detected, auditing nftables ruleset...");
                await AuditNftablesAsync(result);
                firewallFound = true;
            }

            if (!string.IsNullOrWhiteSpace(iptCheck))
            {
                Logger.Debug("iptables detected, auditing iptables ruleset...");
                await AuditIptablesAsync(result);
                firewallFound = true;
            }

            // Check for ufw (Uncomplicated Firewall)
            var ufwCheck = await RunCommandAsync("which ufw 2>/dev/null");
            if (!string.IsNullOrWhiteSpace(ufwCheck))
            {
                Logger.Debug("ufw detected, checking status...");
                await AuditUfwAsync(result);
                firewallFound = true;
            }

            // Check for firewalld
            var fwdCheck = await RunCommandAsync("which firewall-cmd 2>/dev/null");
            if (!string.IsNullOrWhiteSpace(fwdCheck))
            {
                Logger.Debug("firewalld detected, checking status...");
                await AuditFirewalldAsync(result);
                firewallFound = true;
            }

            if (!firewallFound)
            {
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "No Firewall Detected",
                    Severity = "Critical",
                    Description = "No firewall (iptables, nftables, ufw, or firewalld) was detected on this system.",
                    Remediation = "Install and configure a firewall immediately. Recommended: ufw (simple) or nftables (advanced).",
                    Evidence = "No firewall tools found in PATH",
                    Module = "FirewallAuditor",
                    Confidence = 95
                });
            }

            result.Completed = true;
            Logger.Info($"Firewall audit complete: {result.Vulnerabilities.Count} findings.");
        }
        catch (Exception ex)
        {
            result.ErrorMessage = ex.Message;
            Logger.Error($"Firewall auditor failed: {ex.Message}");
        }

        result.EndTime = DateTime.UtcNow;
        return result;
    }

    /// <summary>Audits iptables configuration.</summary>
    private static async Task AuditIptablesAsync(ScanResult result)
    {
        try
        {
            // Check iptables filter table
            var filterOutput = await RunCommandAsync("sudo iptables -L -n -v 2>/dev/null || iptables -L -n -v 2>/dev/null");

            if (string.IsNullOrWhiteSpace(filterOutput) || filterOutput.Contains("Permission denied"))
            {
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "Iptables Permission",
                    Severity = "Info",
                    Description = "Cannot read iptables rules — run with sudo for complete firewall auditing.",
                    Remediation = "Run SecKit with sudo privileges for full firewall analysis.",
                    Module = "FirewallAuditor",
                    Confidence = 100
                });
                return;
            }

            // Parse chains and policies
            var chains = ParseIptablesChains(filterOutput);

            foreach (var (chain, policy, rules) in chains)
            {
                // Check default policies
                switch (chain)
                {
                    case "INPUT":
                        if (policy != "DROP" && policy != "REJECT")
                        {
                            result.Vulnerabilities.Add(new Vulnerability
                            {
                                Type = "Firewall Default Policy",
                                Severity = "Critical",
                                Description = $"iptables INPUT chain default policy is '{policy}' (should be DROP). All traffic is allowed by default.",
                                Remediation = "Run: sudo iptables -P INPUT DROP (ensure you have rules to allow essential traffic first).",
                                Evidence = $"Chain: INPUT | Policy: {policy}",
                                Module = "FirewallAuditor",
                                Confidence = 95
                            });
                        }
                        break;
                    case "FORWARD":
                        if (policy != "DROP" && policy != "REJECT")
                        {
                            result.Vulnerabilities.Add(new Vulnerability
                            {
                                Type = "Firewall Default Policy",
                                Severity = "Medium",
                                Description = $"iptables FORWARD chain default policy is '{policy}'. Forwarded traffic is allowed by default.",
                                Remediation = "Run: sudo iptables -P FORWARD DROP unless this host acts as a router.",
                                Evidence = $"Chain: FORWARD | Policy: {policy}",
                                Module = "FirewallAuditor",
                                Confidence = 80
                            });
                        }
                        break;
                    case "OUTPUT":
                        if (policy != "DROP" && policy != "REJECT")
                        {
                            result.Vulnerabilities.Add(new Vulnerability
                            {
                                Type = "Firewall Default Policy",
                                Severity = "Low",
                                Description = $"iptables OUTPUT chain default policy is '{policy}'. Outbound traffic is unrestricted.",
                                Remediation = "Consider restricting outbound traffic if the server doesn't need to initiate connections.",
                                Evidence = $"Chain: OUTPUT | Policy: {policy}",
                                Module = "FirewallAuditor",
                                Confidence = 50
                            });
                        }
                        break;
                }

                // If no rules at all and default policy is ACCEPT
                if (rules == 0 && (policy == "ACCEPT" || string.IsNullOrEmpty(policy)))
                {
                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = "No Firewall Rules",
                        Severity = "Critical",
                        Description = $"iptables {chain} chain has no rules and the default policy is ACCEPT. All traffic is unrestricted.",
                        Remediation = "Add appropriate iptables rules and set default policy to DROP.",
                        Evidence = $"Chain: {chain} | Rules: 0 | Policy: ACCEPT",
                        Module = "FirewallAuditor",
                        Confidence = 95
                    });
                }
            }

            // Check for rate limiting rules
            var hasRateLimit = filterOutput.Contains("limit", StringComparison.OrdinalIgnoreCase) ||
                              filterOutput.Contains("recent", StringComparison.OrdinalIgnoreCase);
            if (!hasRateLimit && chains.Any(c => c.Chain == "INPUT" && c.Rules > 0))
            {
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "Missing Rate Limiting",
                    Severity = "Medium",
                    Description = "No rate limiting rules detected in iptables. Services may be vulnerable to brute-force attacks.",
                    Remediation = "Add rate limiting for SSH and other services: iptables -A INPUT -p tcp --dport 22 -m recent --update --seconds 60 --hitcount 4 -j DROP",
                    Evidence = "No rate limiting found",
                    Module = "FirewallAuditor",
                    Confidence = 75
                });
            }

            // Check for exposed sensitive ports
            foreach (var (port, service) in SensitivePorts)
            {
                if (filterOutput.Contains($"dpt:{port}", StringComparison.OrdinalIgnoreCase))
                {
                    var lines = filterOutput.Split('\n');
                    foreach (var line in lines)
                    {
                        if (line.Contains($"dpt:{port}", StringComparison.OrdinalIgnoreCase) &&
                            (line.Contains("ACCEPT") || line.Contains("ACCEPT")))
                        {
                            // Check if it's restricted to specific source
                            var isRestricted = line.Contains("0.0.0.0/0") || !line.Contains("0.0.0.0");

                            result.Vulnerabilities.Add(new Vulnerability
                            {
                                Type = "Exposed Sensitive Port",
                                Severity = isRestricted ? "Medium" : "High",
                                Description = $"Sensitive port {port} ({service}) has an ACCEPT rule in iptables. Verify exposure is intentional.",
                                Remediation = isRestricted
                                    ? $"Restrict port {port} to specific source IPs if public access is unnecessary."
                                    : $"Port {port} is open to all. Restrict to specific source IPs or localhost only.",
                                Evidence = $"Port: {port} | Service: {service} | Rule: {line.Trim()}",
                                Module = "FirewallAuditor",
                                Confidence = 80
                            });
                        }
                    }
                }
            }

            // Check NAT table for port forwarding (potential bypass)
            var natOutput = await RunCommandAsync("sudo iptables -L -n -v -t nat 2>/dev/null || iptables -L -n -v -t nat 2>/dev/null");
            if (!string.IsNullOrWhiteSpace(natOutput) && natOutput.Contains("DNAT"))
            {
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "Iptables NAT Rules",
                    Severity = "Low",
                    Description = "NAT/DNAT rules detected. Review port forwarding rules for potential firewall bypasses.",
                    Remediation = "Review NAT rules with: iptables -t nat -L -n -v. Remove unauthorized port forwards.",
                    Evidence = "DNAT rules present",
                    Module = "FirewallAuditor",
                    Confidence = 60
                });
            }

            // Summary
            var totalRules = chains.Sum(c => c.Rules);
            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "Iptables Summary",
                Severity = "Info",
                Description = $"iptables has {totalRules} rules across {chains.Count} chains.",
                Remediation = "Regularly review and audit firewall rules.",
                Evidence = $"Total rules: {totalRules} | Chains: {chains.Count}",
                Module = "FirewallAuditor",
                Confidence = 95
            });
        }
        catch (Exception ex)
        {
            Logger.Debug($"Iptables audit failed: {ex.Message}");
        }
    }

    /// <summary>Audits nftables configuration.</summary>
    private static async Task AuditNftablesAsync(ScanResult result)
    {
        try
        {
            var output = await RunCommandAsync("sudo nft list ruleset 2>/dev/null || nft list ruleset 2>/dev/null");

            if (string.IsNullOrWhiteSpace(output) || output.Contains("Operation not permitted"))
            {
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "Nftables Permission",
                    Severity = "Info",
                    Description = "Cannot read nftables ruleset — run with sudo for complete auditing.",
                    Remediation = "Run SecKit with sudo privileges for full nftables analysis.",
                    Module = "FirewallAuditor",
                    Confidence = 100
                });
                return;
            }

            // Defensive null guard (compiler flow analysis)
            if (output is null) return;

            // Check for default drop policy
            var hasDropPolicy = output.Contains("policy drop", StringComparison.OrdinalIgnoreCase);
            var hasAcceptPolicy = output.Contains("policy accept", StringComparison.OrdinalIgnoreCase);

            if (!hasDropPolicy && hasAcceptPolicy)
            {
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "Nftables Default Policy",
                    Severity = "High",
                    Description = "nftables has ACCEPT as the default policy. Traffic is allowed by default.",
                    Remediation = "Set the default policy to drop: nft add chain inet filter input '{ type filter hook input priority 0; policy drop; }'",
                    Evidence = "Default policy: ACCEPT",
                    Module = "FirewallAuditor",
                    Confidence = 90
                });
            }

            if (string.IsNullOrWhiteSpace(output) || output.Split('\n').Length < 3)
            {
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "Nftables Empty Ruleset",
                    Severity = "Critical",
                    Description = "nftables is installed but the ruleset appears empty or minimal.",
                    Remediation = "Configure nftables with appropriate rules and set default drop policy.",
                    Evidence = $"Ruleset length: {output?.Split('\n').Length ?? 0} lines",
                    Module = "FirewallAuditor",
                    Confidence = 90
                });
                return; // Nothing else to check for empty ruleset
            }

            // Check for exposed sensitive ports
            foreach (var (port, service) in SensitivePorts)
            {
                if (output.Contains($"{port}", StringComparison.OrdinalIgnoreCase))
                {
                    var lines = output.Split('\n');
                    foreach (var line in lines)
                    {
                        if (line.Contains($"{port}", StringComparison.OrdinalIgnoreCase) &&
                            line.Contains("accept", StringComparison.OrdinalIgnoreCase))
                        {
                            result.Vulnerabilities.Add(new Vulnerability
                            {
                                Type = "Nftables Exposed Port",
                                Severity = "Medium",
                                Description = $"Port {port} ({service}) has an accept rule in nftables. Verify exposure is intentional.",
                                Remediation = $"Restrict port {port} to specific source IPs if public access is not required.",
                                Evidence = $"Port: {port} | Service: {service} | Rule: {line.Trim()}",
                                Module = "FirewallAuditor",
                                Confidence = 75
                            });
                        }
                    }
                }
            }

            // Summary
            var ruleCount = 0;
            foreach (var line in output.Split('\n'))
            {
                if (line.Trim().StartsWith("tcp", StringComparison.OrdinalIgnoreCase) ||
                    line.Trim().StartsWith("udp", StringComparison.OrdinalIgnoreCase) ||
                    line.Trim().StartsWith("ip", StringComparison.OrdinalIgnoreCase) ||
                    line.Trim().StartsWith("ct", StringComparison.OrdinalIgnoreCase) ||
                    line.Trim().StartsWith("meta", StringComparison.OrdinalIgnoreCase))
                    ruleCount++;
            }

            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "Nftables Summary",
                Severity = "Info",
                Description = $"nftables ruleset contains approximately {ruleCount} rules.",
                Remediation = "Regularly review and audit nftables rules.",
                Evidence = $"Rules: ~{ruleCount}",
                Module = "FirewallAuditor",
                Confidence = 85
            });
        }
        catch (Exception ex)
        {
            Logger.Debug($"Nftables audit failed: {ex.Message}");
        }
    }

    /// <summary>Checks ufw status.</summary>
    private static async Task AuditUfwAsync(ScanResult result)
    {
        try
        {
            var output = await RunCommandAsync("sudo ufw status verbose 2>/dev/null || ufw status verbose 2>/dev/null");

            if (string.IsNullOrWhiteSpace(output))
            {
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "UFW Permission",
                    Severity = "Info",
                    Description = "Cannot check ufw status — run with sudo.",
                    Remediation = "Run SecKit with sudo for ufw analysis.",
                    Module = "FirewallAuditor",
                    Confidence = 100
                });
                return;
            }

            if (output.Contains("Status: inactive", StringComparison.OrdinalIgnoreCase))
            {
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "UFW Inactive",
                    Severity = "Critical",
                    Description = "UFW is installed but not active. The firewall is not enforcing any rules.",
                    Remediation = "Enable UFW: sudo ufw enable. Configure rules first to avoid lockout.",
                    Evidence = "Status: inactive",
                    Module = "FirewallAuditor",
                    Confidence = 100
                });
            }
            else if (output.Contains("Status: active", StringComparison.OrdinalIgnoreCase))
            {
                Logger.Info("UFW is active and enforcing rules.");

                // Check default policies
                if (output.Contains("Default: allow (incoming)", StringComparison.OrdinalIgnoreCase))
                {
                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = "UFW Default Policy",
                        Severity = "Critical",
                        Description = "UFW default incoming policy is ALLOW. All inbound traffic is permitted by default.",
                        Remediation = "Run: sudo ufw default deny incoming",
                        Evidence = "Default: allow (incoming)",
                        Module = "FirewallAuditor",
                        Confidence = 95
                    });
                }

                // Count rules
                var ruleLines = output.Split('\n').Count(l =>
                    l.Contains("ALLOW", StringComparison.OrdinalIgnoreCase) ||
                    l.Contains("DENY", StringComparison.OrdinalIgnoreCase) ||
                    l.Contains("LIMIT", StringComparison.OrdinalIgnoreCase));

                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "UFW Summary",
                    Severity = "Info",
                    Description = $"UFW is active with approximately {ruleLines} rules.",
                    Remediation = "Regularly review UFW rules with: sudo ufw status numbered",
                    Evidence = $"Rules: ~{ruleLines}",
                    Module = "FirewallAuditor",
                    Confidence = 95
                });
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"UFW audit failed: {ex.Message}");
        }
    }

    /// <summary>Checks firewalld status.</summary>
    private static async Task AuditFirewalldAsync(ScanResult result)
    {
        try
        {
            var output = await RunCommandAsync(
                "sudo firewall-cmd --state 2>/dev/null || firewall-cmd --state 2>/dev/null");

            if (string.IsNullOrWhiteSpace(output))
            {
                Logger.Debug("firewalld not running or permission denied.");
                return;
            }

            if (output.Contains("not running", StringComparison.OrdinalIgnoreCase))
            {
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "Firewalld Not Running",
                    Severity = "High",
                    Description = "firewalld is installed but not running.",
                    Remediation = "Start firewalld: sudo systemctl start firewalld && sudo systemctl enable firewalld",
                    Evidence = "State: not running",
                    Module = "FirewallAuditor",
                    Confidence = 95
                });
            }
            else if (output.Contains("running", StringComparison.OrdinalIgnoreCase))
            {
                Logger.Info("firewalld is running.");

                // Get default zone
                var zoneOutput = await RunCommandAsync(
                    "sudo firewall-cmd --get-default-zone 2>/dev/null || firewall-cmd --get-default-zone 2>/dev/null");

                if (!string.IsNullOrWhiteSpace(zoneOutput))
                {
                    // List services in default zone
                    var servicesOutput = await RunCommandAsync(
                        $"sudo firewall-cmd --list-services --zone={zoneOutput.Trim()} 2>/dev/null || " +
                        $"firewall-cmd --list-services --zone={zoneOutput.Trim()} 2>/dev/null");

                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = "Firewalld Summary",
                        Severity = "Info",
                        Description = $"firewalld is running. Default zone: {zoneOutput.Trim()}. Allowed services: {servicesOutput?.Trim() ?? "unknown"}",
                        Remediation = "Review firewalld configuration: firewall-cmd --list-all",
                        Evidence = $"Zone: {zoneOutput.Trim()}",
                        Module = "FirewallAuditor",
                        Confidence = 90
                    });
                }
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"Firewalld audit failed: {ex.Message}");
        }
    }

    /// <summary>Parses iptables -L -n -v output into chain information.</summary>
    private static List<(string Chain, string Policy, int Rules)> ParseIptablesChains(string output)
    {
        var chains = new List<(string Chain, string Policy, int Rules)>();
        string? currentChain = null;
        string? currentPolicy = null;
        int currentRules = 0;

        foreach (var line in output.Split('\n'))
        {
            var trimmed = line.Trim();

            // Chain header: "Chain INPUT (policy ACCEPT 0 packets, 0 bytes)"
            if (trimmed.StartsWith("Chain ", StringComparison.OrdinalIgnoreCase))
            {
                // Save previous chain
                if (currentChain is not null)
                    chains.Add((currentChain, currentPolicy ?? "ACCEPT", currentRules));

                var parts = trimmed.Split(new[] { ' ', '(' }, StringSplitOptions.RemoveEmptyEntries);
                currentChain = parts.Length > 1 ? parts[1] : "unknown";
                currentPolicy = "ACCEPT";
                currentRules = 0;

                // Extract policy
                if (trimmed.Contains("policy", StringComparison.OrdinalIgnoreCase))
                {
                    var policyStart = trimmed.IndexOf("policy", StringComparison.OrdinalIgnoreCase);
                    if (policyStart >= 0)
                    {
                        var policyPart = trimmed[(policyStart + 7)..].Trim();
                        var policyEnd = policyPart.IndexOf(' ');
                        if (policyEnd > 0)
                            currentPolicy = policyPart[..policyEnd].ToUpper();
                    }
                }
            }
            // Rule line (starts with pkts/bytes counters, then target)
            else if (currentChain is not null && !string.IsNullOrWhiteSpace(trimmed) &&
                     !trimmed.StartsWith("pkts", StringComparison.OrdinalIgnoreCase))
            {
                // Lines with numeric counters at start are rules
                if (char.IsDigit(trimmed[0]) || trimmed.StartsWith("target", StringComparison.OrdinalIgnoreCase))
                    currentRules++;
            }
        }

        // Save last chain
        if (currentChain is not null)
            chains.Add((currentChain, currentPolicy ?? "ACCEPT", currentRules));

        return chains;
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
