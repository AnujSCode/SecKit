#pragma warning disable CS1998
using System.Text;
using SecKit.Core;
using SecKit.Models;

namespace SecKit.Modules.Analysis;

/// <summary>
/// Correlates vulnerabilities from multiple scan modules to identify attack chains,
/// compute an overall risk score (0-100), and produce a prioritized fix list.
/// Models how defenders think: an open port alone is noise, but open SSH + weak
/// credentials + an outdated kernel is an incident waiting to happen.
/// </summary>
public class VulnCorrelator
{
    private readonly ConfigManager _config;

    public VulnCorrelator(ConfigManager config)
    {
        _config = config;
    }

    /// <summary>
    /// Analyzes a collection of scan results to identify attack chains,
    /// compute risk scores, and produce a prioritized remediation plan.
    /// </summary>
    /// <param name="moduleResults">Scan results from all completed modules.</param>
    /// <returns>A scan result containing correlated findings and recommendations.</returns>
    public async Task<ScanResult> ScanAsync(List<ScanResult> moduleResults)
    {
        var result = new ScanResult
        {
            ModuleName = "Vulnerability Correlator",
            TargetUrl = "correlation",
            StartTime = DateTime.UtcNow
        };

        try
        {
            // Aggregate all vulnerabilities
            var allVulns = moduleResults
                .SelectMany(r => r.Vulnerabilities)
                .ToList();

            result.RequestsSent = moduleResults.Sum(r => r.RequestsSent);
            result.EndpointsTested = moduleResults.Sum(r => r.EndpointsTested);

            Logger.Info($"Correlating {allVulns.Count} vulnerabilities from {moduleResults.Count} modules...");

            // 1. Identify attack chains
            IdentifyAttackChains(result, allVulns);

            // 2. Compute risk score
            var riskScore = ComputeRiskScore(allVulns);
            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "Overall Risk Score",
                Severity = riskScore >= 80 ? "Critical" : riskScore >= 50 ? "High" : riskScore >= 25 ? "Medium" : "Low",
                Url = "N/A",
                Parameter = "Risk Assessment",
                Payload = riskScore.ToString("F0"),
                Description = $"Overall security risk score: {riskScore:F0}/100. " +
                    (riskScore >= 80 ? "Immediate action required." :
                     riskScore >= 50 ? "Significant risk — prioritize fixes." :
                     riskScore >= 25 ? "Moderate risk — address within sprint." : "Low risk — address as time permits."),
                Evidence = $"{allVulns.Count(v => v.Severity == "Critical")} critical, " +
                           $"{allVulns.Count(v => v.Severity == "High")} high, " +
                           $"{allVulns.Count(v => v.Severity == "Medium")} medium vulns",
                Remediation = "Address Critical and High severity findings first, then work through Medium and Low items.",
                Module = "VulnCorrelator",
                Confidence = 85
            });

            // 3. Produce prioritized fix list
            ProducePrioritizedFixList(result, allVulns);

            // 4. Module coverage assessment
            AssessModuleCoverage(result, moduleResults);

            result.Completed = true;
        }
        catch (Exception ex)
        {
            result.ErrorMessage = ex.Message;
            Logger.Error($"Vulnerability Correlator failed: {ex.Message}");
        }

        result.EndTime = DateTime.UtcNow;
        return result;
    }

    /// <summary>
    /// Identifies attack chains by linking vulnerabilities across modules.
    /// An attack chain is a sequence of vulnerabilities that together enable
    /// a significant compromise.
    /// </summary>
    private void IdentifyAttackChains(ScanResult result, List<Vulnerability> vulns)
    {
        // Chain 1: Open SSH + weak credentials + outdated kernel → RCE + root
        var openSsh = vulns.Any(v => v.Module == "PortScanner" && v.Url.Contains(":22"));
        var weakCreds = vulns.Any(v => v.Type.Contains("Weak Credentials"));
        var sqlInjection = vulns.Any(v => v.Type.Contains("SQL Injection") && v.Severity is "Critical" or "High");

        if (openSsh && weakCreds)
        {
            AddChain(result, "SSH Brute Force → System Compromise",
                "Attack chain: open SSH port + weak credentials → attacker gains shell access. " +
                "If combined with privilege escalation vulns, this leads to full compromise.",
                "Critical", 95,
                "1) Restrict SSH to specific IPs with firewall rules\n" +
                "2) Enforce SSH key-only authentication\n" +
                "3) Enable fail2ban with aggressive thresholds\n" +
                "4) Audit all user accounts for weak passwords");
        }

        // Chain 2: SQLi + file write → shell upload → server compromise
        if (sqlInjection)
        {
            var fileUpload = vulns.Any(v => v.Type.Contains("File Upload"));
            if (fileUpload)
            {
                AddChain(result, "SQLi → File Upload → Shell Access",
                    "Attack chain: SQL injection enables data extraction; combined with file upload vulnerability, " +
                    "an attacker can upload a webshell and gain persistent access.",
                    "Critical", 90,
                    "1) Fix SQL injection with parameterized queries\n" +
                    "2) Implement strict file upload validation (extensions, MIME, content scanning)\n" +
                    "3) Store uploads outside web root\n" +
                    "4) Scan all uploaded files for known webshells");
            }

            // Chain: SQLi → credential dump → lateral movement
            AddChain(result, "SQLi → Database Dump → Credential Exposure",
                "Attack chain: SQL injection enables reading database contents, including password hashes. " +
                "If hashing is weak, plaintext credentials lead to lateral movement.",
                "Critical", 90,
                "1) Fix SQL injection with parameterized queries\n" +
                "2) Use strong password hashing (bcrypt/argon2) with per-user salts\n" +
                "3) Implement database access logging and alerting\n" +
                "4) Rotate all database credentials after fixing");
        }

        // Chain 3: CORS misconfig + auth tokens → session hijacking
        var corsReflection = vulns.Any(v => v.Type.Contains("CORS") && v.Severity is "Critical" or "High");
        var authIssues = vulns.Any(v => v.Type.Contains("JWT") || v.Type.Contains("Auth") || v.Type.Contains("Session"));

        if (corsReflection && authIssues)
        {
            AddChain(result, "CORS Misconfig → Session Hijacking",
                "Attack chain: CORS allows arbitrary origins to read responses that may contain auth tokens or session cookies. " +
                "Combined with auth vulnerabilities, this enables session hijacking.",
                "High", 85,
                "1) Fix CORS to use exact origin whitelist\n" +
                "2) Set SameSite=Strict on all session cookies\n" +
                "3) Implement token binding or sender-constrained tokens\n" +
                "4) Rotate all sessions after fixing");
        }

        // Chain 4: Open sensitive port + no firewall → direct database access
        var openDbPorts = vulns.Any(v => v.Module == "PortScanner" && v.Url.Contains(":3306"));
        var openRedis = vulns.Any(v => v.Module == "PortScanner" && v.Url.Contains(":6379"));
        var openMongo = vulns.Any(v => v.Module == "PortScanner" && v.Url.Contains(":27017"));

        if (openDbPorts || openRedis || openMongo)
        {
            var dbName = openDbPorts ? "MySQL" : openRedis ? "Redis" : "MongoDB";
            AddChain(result, $"Open {dbName} Port → Data Exfiltration",
                $"Attack chain: {dbName} port is internet-accessible. An attacker can attempt brute force, " +
                "exploit known vulnerabilities, or read unauthenticated data.",
                "Critical", 95,
                $"1) Bind {dbName} to 127.0.0.1 or private network only\n" +
                "2) Use a VPN or SSH tunnel for remote database access\n" +
                "3) Enable authentication with strong passwords\n" +
                "4) Implement network ACLs to restrict access");
        }

        // Chain 5: XSS + Session Management → Account Takeover
        var xss = vulns.Any(v => v.Type.Contains("XSS") && v.Severity is "Critical" or "High");
        if (xss && authIssues)
        {
            AddChain(result, "XSS → Session Theft → Account Takeover",
                "Attack chain: Stored/reflected XSS enables cookie theft. Combined with auth issues, " +
                "an attacker can hijack user sessions and take over accounts.",
                "Critical", 90,
                "1) Fix XSS with context-aware output encoding\n" +
                "2) Set HttpOnly and Secure flags on session cookies\n" +
                "3) Implement Content Security Policy headers\n" +
                "4) Use SameSite=Strict for all cookies");
        }

        // Chain 6: GraphQL introspection + sensitive fields → data exfiltration
        var gqlIntro = vulns.Any(v => v.Type.Contains("GraphQL") && v.Type.Contains("Introspection"));
        var gqlSensitive = vulns.Any(v => v.Type.Contains("GraphQL") && v.Type.Contains("Sensitive"));

        if (gqlIntro && gqlSensitive)
        {
            AddChain(result, "GraphQL Introspection → Data Exfiltration",
                "Attack chain: GraphQL introspection exposed the full schema, and the schema contains sensitive fields " +
                "(passwords, tokens, keys) — an attacker can craft queries to extract this data.",
                "Critical", 90,
                "1) Disable introspection in production\n" +
                "2) Remove sensitive fields from the schema or apply field-level auth\n" +
                "3) Implement query cost/complexity analysis\n" +
                "4) Add rate limiting on GraphQL endpoints");
        }

        // Chain 7: S3 public bucket + sensitive files → data breach
        var s3Public = vulns.Any(v => v.Module == "S3BucketScanner" &&
            (v.Type.Contains("Public") || v.Type.Contains("Overly Permissive")));
        var s3NoEncrypt = vulns.Any(v => v.Module == "S3BucketScanner" && v.Type.Contains("Encryption"));

        if (s3Public)
        {
            AddChain(result, "S3 Public Bucket → Data Exposure",
                "Attack chain: S3 bucket is publicly accessible. Any files stored in it are exposed to the internet. " +
                (s3NoEncrypt ? "Additionally, data is stored unencrypted." : ""),
                "Critical", 95,
                "1) Enable all S3 public access block settings\n" +
                "2) Remove public ACLs and bucket policies\n" +
                "3) Enable default encryption (SSE-S3 or SSE-KMS)\n" +
                "4) Audit bucket contents for sensitive data\n" +
                "5) Enable S3 access logging");
        }

        // Chain 8: IAM overprivileged + no MFA → privilege escalation
        var iamNoMfa = vulns.Any(v => v.Module == "IamAuditor" && v.Type.Contains("No MFA"));
        var iamAdmin = vulns.Any(v => v.Module == "IamAuditor" && v.Type.Contains("Admin"));
        var rootKeys = vulns.Any(v => v.Module == "IamAuditor" && v.Type.Contains("Root Has Access Keys"));

        if (rootKeys)
        {
            AddChain(result, "Root Access Keys → Full Account Takeover",
                "Attack chain: The AWS root account has active access keys. If leaked, an attacker gains unrestricted " +
                "access to the entire AWS account including billing and account deletion.",
                "Critical", 100,
                "1) Delete all root access keys immediately\n" +
                "2) Enable MFA on root account (hardware MFA preferred)\n" +
                "3) Create IAM users with least privilege for day-to-day tasks\n" +
                "4) Review CloudTrail for root account activity");
        }
    }

    /// <summary>
    /// Computes an overall risk score (0-100) based on the count and severity of vulnerabilities.
    /// Weighting: Critical = 10, High = 5, Medium = 3, Low = 1.
    /// The score is normalized and clamped to 0-100.
    /// </summary>
    private double ComputeRiskScore(List<Vulnerability> vulns)
    {
        if (vulns.Count == 0) return 0;

        var critical = vulns.Count(v => v.Severity == "Critical");
        var high = vulns.Count(v => v.Severity == "High");
        var medium = vulns.Count(v => v.Severity == "Medium");
        var low = vulns.Count(v => v.Severity == "Low");

        double rawScore = critical * 10 + high * 5 + medium * 3 + low * 1;

        // Normalize: cap theoretical max at 100
        double score = Math.Min(rawScore, 100);

        // Add a baseline for any critical finding
        if (critical > 0)
            score = Math.Max(score, 60 + Math.Min(critical * 10, 40));

        // Bonus for attack chain existence (attack chains multiply risk)
        if (critical >= 2 || (critical >= 1 && high >= 3))
            score = Math.Min(score + 10, 100);

        return Math.Round(score, 0);
    }

    /// <summary>
    /// Produces a prioritized fix list sorted by severity → confidence.
    /// </summary>
    private void ProducePrioritizedFixList(ScanResult result, List<Vulnerability> vulns)
    {
        var prioritized = vulns
            .OrderByDescending(v => v.Severity switch
            {
                "Critical" => 5,
                "High" => 4,
                "Medium" => 3,
                "Low" => 2,
                _ => 1
            })
            .ThenByDescending(v => v.Confidence)
            .ToList();

        // Top 5 most critical items to fix
        var top5 = prioritized.Take(5).ToList();
        if (top5.Count > 0)
        {
            var sb = new StringBuilder();
            sb.AppendLine("=== TOP PRIORITY FIXES ===");
            for (int i = 0; i < top5.Count; i++)
            {
                sb.AppendLine($"{i + 1}. [{top5[i].Severity.ToUpper()}] {top5[i].Type}");
                sb.AppendLine($"   URL: {top5[i].Url}");
                sb.AppendLine($"   Fix: {top5[i].Remediation}");
                sb.AppendLine();
            }

            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "Prioritized Fix List",
                Severity = "Info",
                Url = "N/A",
                Parameter = "Prioritization",
                Payload = $"{top5.Count} top items",
                Description = sb.ToString(),
                Evidence = $"Total vulns: {vulns.Count}",
                Remediation = "Address in order of priority. Start with Critical, then High.",
                Module = "VulnCorrelator",
                Confidence = 100
            });
        }
    }

    /// <summary>
    /// Assesses which areas were covered by the scan and what's missing.
    /// </summary>
    private void AssessModuleCoverage(ScanResult result, List<ScanResult> moduleResults)
    {
        var modulesRun = moduleResults
            .Where(r => r.Completed)
            .Select(r => r.ModuleName)
            .ToHashSet();

        var allModules = new[]
        {
            "Port Scanner", "SSL Checker", "Header Analyzer",
            "SQL Injection Tester", "XSS Tester", "CSRF Tester",
            "Auth Tester", "SSRF Tester", "Path Traversal Tester",
            "File Upload Tester",
            "JWT Analyzer", "CORS Scanner", "Credential Tester",
            "GraphQL Auditor",
            "S3 Bucket Scanner", "IAM Auditor", "Security Group Auditor",
        };

        var missing = allModules.Where(m => !modulesRun.Contains(m)).ToList();

        if (missing.Count > 0)
        {
            var msg = $"The following security areas were not scanned: {string.Join(", ", missing)}. " +
                      "Consider running a full scan for complete coverage.";
            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "Incomplete Coverage",
                Severity = "Low",
                Url = "N/A",
                Parameter = "Coverage",
                Payload = string.Join(", ", missing),
                Description = msg,
                Remediation = "Run a full scan with all modules enabled.",
                Module = "VulnCorrelator",
                Confidence = 100
            });
        }
    }

    private void AddChain(ScanResult result, string name, string description,
        string severity, int confidence, string remediation)
    {
        result.Vulnerabilities.Add(new Vulnerability
        {
            Type = $"Attack Chain: {name}",
            Severity = severity,
            Url = "N/A",
            Parameter = "Attack Chain",
            Payload = name,
            Description = description,
            Evidence = "Cross-module correlation",
            Remediation = remediation,
            Module = "VulnCorrelator",
            Confidence = confidence
        });
        Logger.LogVulnerability(result.Vulnerabilities.Last());
    }
}
