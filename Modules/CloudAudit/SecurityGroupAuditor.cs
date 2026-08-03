using SecKit.Core;
using SecKit.Models;

namespace SecKit.Modules.CloudAudit;

/// <summary>
/// Audits AWS EC2 security groups for dangerous inbound rules:
/// sensitive ports open to the world (0.0.0.0/0, ::/0), unused groups,
/// overlapping rules, and best-practice recommendations.
/// </summary>
public class SecurityGroupAuditor
{
    private readonly ConfigManager _config;

    // Sensitive ports that should never be open to 0.0.0.0/0
    private static readonly Dictionary<int, string> SensitivePorts = new()
    {
        {22, "SSH"},
        {3389, "RDP"},
        {3306, "MySQL"},
        {5432, "PostgreSQL"},
        {1433, "MSSQL"},
        {1521, "Oracle"},
        {6379, "Redis"},
        {27017, "MongoDB"},
        {11211, "Memcached"},
        {9200, "Elasticsearch"},
        {5601, "Kibana"},
        {2375, "Docker (unencrypted)"},
        {2376, "Docker (TLS)"},
        {5000, "Docker Registry"},
        {6443, "Kubernetes API"},
        {10250, "Kubelet API"},
        {9090, "Prometheus"},
        {3000, "Grafana"},
        {25, "SMTP"},
        {110, "POP3"},
        {143, "IMAP"},
        {389, "LDAP"},
        {636, "LDAPS"},
        {873, "Rsync"},
        {2049, "NFS"},
        {8080, "HTTP Alt"},
        {8443, "HTTPS Alt"},
        {4000, "Debug Server"},
        {8000, "Dev Server"},
        {9000, "PHP-FPM"},
        {4040, "ngrok"},
        {54321, "Misc Management"},
    };

    // Ports that are commonly open and should be reviewed
    private static readonly Dictionary<int, string> ReviewPorts = new()
    {
        {80, "HTTP"},
        {443, "HTTPS"},
        {53, "DNS"},
        {123, "NTP"},
        {443, "HTTPS"},
    };

    // Private/bogon ranges that shouldn't appear in overly broad rules
    private static readonly string[] CidrWorld = { "0.0.0.0/0", "::/0" };

    public SecurityGroupAuditor(ConfigManager config)
    {
        _config = config;
    }

    /// <summary>Audits all EC2 security groups for dangerous inbound rules.</summary>
    public async Task<ScanResult> ScanAsync(string target = "aws")
    {
        var result = new ScanResult
        {
            ModuleName = "Security Group Auditor",
            TargetUrl = target,
            StartTime = DateTime.UtcNow
        };

        try
        {
            string? credsError = CheckAwsCredentials();
            if (credsError != null)
            {
                AddInfoVuln(result, "AWS Credentials Not Configured",
                    $"Cannot audit security groups: {credsError}",
                    "Set AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_REGION.");
                result.Completed = true;
                result.EndTime = DateTime.UtcNow;
                return result;
            }

            using var ec2Client = new Amazon.EC2.AmazonEC2Client();

            // Fetch all security groups
            result.RequestsSent++;
            var sgResponse = await ec2Client.DescribeSecurityGroupsAsync(
                new Amazon.EC2.Model.DescribeSecurityGroupsRequest());

            var groups = sgResponse.SecurityGroups;
            result.EndpointsTested = groups.Count;
            Logger.Info($"Found {groups.Count} security group(s).");

            // Track used groups for unused-group detection
            var usedGroups = await GetUsedSecurityGroupIdsAsync(ec2Client, result);

            foreach (var group in groups)
            {
                // Check inbound rules on sensitive ports
                foreach (var rule in group.IpPermissions)
                {
                    if (rule.FromPort <= 0 && rule.ToPort <= 0) continue; // All traffic

                    for (int port = rule.FromPort; port <= rule.ToPort; port++)
                    {
                        CheckRuleOpenToWorld(result, group, rule, port);
                    }
                }

                // Check for 0.0.0.0/0 on -1 (all traffic)
                CheckAllTrafficOpen(result, group);

                // Check for unused groups
                if (!usedGroups.Contains(group.GroupId))
                {
                    AddVuln(result, $"sg:{group.GroupId}", $"Unused Security Group ({group.GroupName})",
                        $"Security group '{group.GroupName}' ({group.GroupId}) is not associated with any EC2 instance, ELB, RDS, Lambda, or ENI.",
                        "Low", 70,
                        "Delete unused security groups to reduce attack surface and confusion.",
                        group);
                }

                // Check for overlapping/duplicate rules
                CheckOverlappingRules(result, group);
            }

            result.Completed = true;
        }
        catch (Amazon.EC2.AmazonEC2Exception awsEx)
        {
            result.ErrorMessage = $"AWS EC2 error: {awsEx.Message}";
            Logger.Error($"Security Group Auditor AWS error: {awsEx.Message}");
        }
        catch (Exception ex)
        {
            result.ErrorMessage = ex.Message;
            Logger.Error($"Security Group Auditor failed: {ex.Message}");
        }

        result.EndTime = DateTime.UtcNow;
        return result;
    }

    /// <summary>Checks if a specific port rule is open to the world.</summary>
    private void CheckRuleOpenToWorld(ScanResult result, Amazon.EC2.Model.SecurityGroup group,
        Amazon.EC2.Model.IpPermission rule, int port)
    {
        if (!SensitivePorts.ContainsKey(port)) return;

        foreach (var ipRange in rule.Ipv4Ranges)
        {
            if (ipRange.CidrIp == "0.0.0.0/0")
            {
                var service = SensitivePorts[port];
                AddVuln(result, $"sg:{group.GroupId}",
                    $"Critical: {service} (port {port}) Open to World",
                    $"Security group '{group.GroupName}' allows {service} from 0.0.0.0/0 (anyone on the internet). This is a critical exposure.",
                    "Critical", 100,
                    $"Restrict {service} access to specific IPs or use a VPN/bastion host. Run: aws ec2 revoke-security-group-ingress --group-id {group.GroupId} --protocol tcp --port {port} --cidr 0.0.0.0/0",
                    group);
            }
            else if (ipRange.CidrIp != "0.0.0.0/0" && !ipRange.CidrIp.StartsWith("10.") &&
                     !ipRange.CidrIp.StartsWith("172.16.") && !ipRange.CidrIp.StartsWith("192.168."))
            {
                // Check for overly broad non-RFC1918 ranges
                var parts = ipRange.CidrIp.Split('/');
                if (parts.Length == 2 && int.TryParse(parts[1], out var prefix) && prefix <= 16)
                {
                    var service = SensitivePorts[port];
                    AddVuln(result, $"sg:{group.GroupId}",
                        $"Broad: {service} (port {port}) Open to /{prefix}",
                        $"Security group '{group.GroupName}' allows {service} from {ipRange.CidrIp} (very broad range).",
                        "High", 70,
                        $"Tighten the CIDR range for {service} access. Restrict to specific IPs or private VPC ranges.",
                        group);
                }
            }
        }

        foreach (var ipv6Range in rule.Ipv6Ranges)
        {
            if (ipv6Range.CidrIpv6 == "::/0" && SensitivePorts.ContainsKey(port))
            {
                var service = SensitivePorts[port];
                AddVuln(result, $"sg:{group.GroupId}",
                    $"Critical: {service} (port {port}) Open to IPv6 World",
                    $"Security group '{group.GroupName}' allows {service} from ::/0 (all IPv6 addresses).",
                    "Critical", 100,
                    $"Restrict {service} access. Remove ::/0 from IPv6 inbound rules for port {port}.",
                    group);
            }
        }
    }

    /// <summary>Checks for rules allowing all traffic from anywhere.</summary>
    private void CheckAllTrafficOpen(ScanResult result, Amazon.EC2.Model.SecurityGroup group)
    {
        foreach (var rule in group.IpPermissions)
        {
            if (rule.IpProtocol == "-1") // All protocols
            {
                foreach (var ipRange in rule.Ipv4Ranges)
                {
                    if (ipRange.CidrIp == "0.0.0.0/0")
                    {
                        AddVuln(result, $"sg:{group.GroupId}",
                            "CRITICAL: All Traffic Open to World",
                            $"Security group '{group.GroupName}' allows ALL traffic (all protocols, all ports) from 0.0.0.0/0. This is an extreme security risk.",
                            "Critical", 100,
                            $"Delete this rule immediately. Use specific port/protocol rules with restricted CIDRs. Run: aws ec2 revoke-security-group-ingress --group-id {group.GroupId} --protocol -1 --cidr 0.0.0.0/0",
                            group);
                        return;
                    }
                }
                foreach (var ipv6Range in rule.Ipv6Ranges)
                {
                    if (ipv6Range.CidrIpv6 == "::/0")
                    {
                        AddVuln(result, $"sg:{group.GroupId}",
                            "CRITICAL: All Traffic Open to IPv6 World",
                            $"Security group '{group.GroupName}' allows ALL traffic from ::/0 (all IPv6 addresses).",
                            "Critical", 100,
                            "Delete this rule immediately. Restrict to specific ports and CIDRs.",
                            group);
                        return;
                    }
                }
            }
        }
    }

    /// <summary>Detects overlapping/duplicate inbound rules in a security group.</summary>
    private void CheckOverlappingRules(ScanResult result, Amazon.EC2.Model.SecurityGroup group)
    {
        var rules = new List<(int From, int To, string Proto, string Cidr)>();

        foreach (var rule in group.IpPermissions)
        {
            foreach (var ipRange in rule.Ipv4Ranges)
            {
                rules.Add((rule.FromPort, rule.ToPort, rule.IpProtocol, ipRange.CidrIp));
            }
        }

        // Check for duplicates
        var seen = new HashSet<string>();
        foreach (var (from, to, proto, cidr) in rules)
        {
            var key = $"{from}-{to}-{proto}-{cidr}";
            if (!seen.Add(key))
            {
                AddVuln(result, $"sg:{group.GroupId}",
                    "Duplicate Security Group Rule",
                    $"Security group '{group.GroupName}' has duplicate rule: {proto} {from}-{to} from {cidr}.",
                    "Info", 40,
                    "Remove duplicate rules to simplify management.",
                    group);
                break; // One finding per group is sufficient
            }
        }

        // Check for port ranges that could be split/overlap
        if (rules.Count > 20)
        {
            AddVuln(result, $"sg:{group.GroupId}",
                "Large Number of Security Group Rules",
                $"Security group '{group.GroupName}' has {rules.Count} inbound rules. This is complex to manage and prone to mistakes.",
                "Low", 40,
                "Consolidate rules. Use prefix lists or reference security groups instead of many CIDR-based rules.",
                group);
        }
    }

    /// <summary>Gathers security group IDs that are actively in use.</summary>
    private async Task<HashSet<string>> GetUsedSecurityGroupIdsAsync(
        Amazon.EC2.AmazonEC2Client client, ScanResult result)
    {
        var used = new HashSet<string>();

        try
        {
            // Collect from ENIs (network interfaces)
            result.RequestsSent++;
            var eniResponse = await client.DescribeNetworkInterfacesAsync(
                new Amazon.EC2.Model.DescribeNetworkInterfacesRequest());

            foreach (var eni in eniResponse.NetworkInterfaces)
            {
                foreach (var sg in eni.Groups)
                    used.Add(sg.GroupId);
            }

            // Collect from EC2 instances directly
            result.RequestsSent++;
            var instanceResponse = await client.DescribeInstancesAsync(
                new Amazon.EC2.Model.DescribeInstancesRequest());

            foreach (var reservation in instanceResponse.Reservations)
            {
                foreach (var instance in reservation.Instances)
                {
                    foreach (var sg in instance.SecurityGroups)
                        used.Add(sg.GroupId);
                }
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"Used SG collection failed: {ex.Message}");
        }

        return used;
    }

    // --- Helpers ---

    private static string? CheckAwsCredentials()
    {
        if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("AWS_ACCESS_KEY_ID")) &&
            !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("AWS_SECRET_ACCESS_KEY")))
            return null;

        var credsPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".aws", "credentials");
        if (File.Exists(credsPath)) return null;

        var configPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".aws", "config");
        if (File.Exists(configPath)) return null;

        try
        {
            var metadataUrl = Environment.GetEnvironmentVariable("ECS_CONTAINER_METADATA_URI_V4");
            if (!string.IsNullOrEmpty(metadataUrl)) return null;
        }
        catch { }

        return "No AWS credentials found.";
    }

    private void AddVuln(ScanResult result, string url, string type, string description,
        string severity, int confidence, string remediation, Amazon.EC2.Model.SecurityGroup sg)
    {
        var vuln = new Vulnerability
        {
            Type = type,
            Severity = severity,
            Url = url,
            Parameter = $"Security Group: {sg.GroupName}",
            Payload = "",
            Description = description,
            Evidence = $"Group: {sg.GroupName} ({sg.GroupId}), VPC: {sg.VpcId}",
            Remediation = remediation,
            Module = "SecurityGroupAuditor",
            Confidence = confidence
        };
        result.Vulnerabilities.Add(vuln);
        Logger.LogVulnerability(vuln);
    }

    private void AddInfoVuln(ScanResult result, string type, string description, string remediation)
    {
        var vuln = new Vulnerability
        {
            Type = type,
            Severity = "Info",
            Url = "N/A",
            Parameter = "Configuration",
            Payload = "",
            Description = description,
            Remediation = remediation,
            Module = "SecurityGroupAuditor",
            Confidence = 100
        };
        result.Vulnerabilities.Add(vuln);
        Logger.LogVulnerability(vuln);
    }
}
