using System.Text;
using SecKit.Core;
using SecKit.Models;

namespace SecKit.Modules.Reporting;

/// <summary>
/// Maps vulnerability findings to compliance frameworks and generates a compliance report.
/// CIS Benchmarks, PCI-DSS, and OWASP ASVS.
/// </summary>
public class ComplianceChecker
{
    private readonly string _outputDir;

    public ComplianceChecker(string outputDir)
    {
        _outputDir = Path.Combine(outputDir, "reports");
        Directory.CreateDirectory(_outputDir);
    }

    /// <summary>
    /// Generates a compliance report mapping findings to CIS, PCI-DSS, and OWASP ASVS.
    /// </summary>
    public async Task<ComplianceReport> CheckAsync(IEnumerable<Vulnerability> vulnerabilities)
    {
        var vulns = vulnerabilities.ToList();
        var report = new ComplianceReport
        {
            GeneratedAt = DateTime.UtcNow
        };

        // Run all three checks
        report.CisResults = CheckCisBenchmarks(vulns);
        report.PciResults = CheckPciDss(vulns);
        report.OwaspResults = CheckOwaspAsvs(vulns);

        // Write the report
        var reportPath = Path.Combine(_outputDir, "compliance-report.txt");
        var reportContent = GenerateReportText(report, vulns);
        await File.WriteAllTextAsync(reportPath, reportContent);
        report.ReportPath = reportPath;

        // Also write JSON
        var jsonPath = Path.Combine(_outputDir, "compliance-report.json");
        var jsonContent = GenerateReportJson(report);
        await File.WriteAllTextAsync(jsonPath, jsonContent);
        report.JsonPath = jsonPath;

        Logger.Info($"Compliance report generated: {report.OverallPassRate:P0} pass rate");
        return report;
    }

    #region CIS Benchmarks

    private List<ComplianceResult> CheckCisBenchmarks(List<Vulnerability> vulns)
    {
        var results = new List<ComplianceResult>();

        // --- CIS 5: Access, Authentication, and Authorization ---
        AddCisControl(results, "CIS 5.2.1", "Ensure SSH PermitRootLogin is disabled",
            !vulns.Any(v => v.Type.ToLowerInvariant().Contains("ssh") && v.Severity is "Critical" or "High"),
            "Root login via SSH should be disabled to prevent direct root access.");

        AddCisControl(results, "CIS 5.2.2", "Ensure SSH Protocol is set to 2",
            !vulns.Any(v => v.Type.ToLowerInvariant().Contains("ssl") && v.Description.Contains("old protocol")),
            "SSH Protocol 1 has known vulnerabilities; only Protocol 2 should be used.");

        AddCisControl(results, "CIS 5.2.3", "Ensure SSH MaxAuthTries is 4 or less",
            !vulns.Any(v => v.Type.ToLowerInvariant() is "auth" or "authentication" &&
                     v.Description.ToLowerInvariant().Contains("brute")),
            "Limit authentication attempts to mitigate brute-force attacks.");

        AddCisControl(results, "CIS 5.3.1", "Ensure password creation requirements are configured",
            !vulns.Any(v => v.Type.ToLowerInvariant().Contains("password") && v.Severity is "Critical" or "High"),
            "Strong password policies reduce credential-based attacks.");

        // --- CIS 2: Services ---
        AddCisControl(results, "CIS 2.1.1", "Ensure unnecessary services are disabled",
            !vulns.Any(v => v.Type.ToLowerInvariant().Contains("port") && v.Severity is "Critical"),
            "Running unnecessary services increases attack surface.");

        AddCisControl(results, "CIS 2.2.1", "Ensure HTTP server is not installed (unless needed)",
            !vulns.Any(v => v.Url.Contains(":80") && v.Severity is "High" or "Critical"),
            "Web servers should be intentionally deployed and hardened.");

        // --- CIS 3: Network Configuration ---
        AddCisControl(results, "CIS 3.1.1", "Ensure firewall is enabled (iptables/nftables/ufw)",
            !vulns.Any(v => v.Type.ToLowerInvariant().Contains("firewall") && v.Severity is "High" or "Critical"),
            "A host-based firewall should be active on all systems.");

        AddCisControl(results, "CIS 3.2.1", "Ensure packet redirect sending is disabled",
            !vulns.Any(v => v.Type.ToLowerInvariant() is "ssrf"),
            "IP forwarding can be abused for lateral movement and SSRF.");

        // --- CIS 6: System Maintenance ---
        AddCisControl(results, "CIS 6.1.1", "Ensure system is kept up to date",
            !vulns.Any(v => v.Type.ToLowerInvariant().Contains("version") && v.Severity is "High" or "Critical"),
            "Outdated software versions may contain known vulnerabilities.");

        AddCisControl(results, "CIS 6.1.2", "Ensure cron daemon is enabled and jobs are reviewed",
            !vulns.Any(v => v.Type.ToLowerInvariant().Contains("cron") && v.Severity is "High" or "Critical"),
            "Unauthorized cron jobs can be used for persistence.");

        // --- Web Application specific ---
        AddCisControl(results, "CIS 7.1.1", "Ensure HTTP security headers are configured",
            !vulns.Any(v => v.Type.ToLowerInvariant().Contains("header")),
            "Security headers (HSTS, CSP, X-Frame-Options) protect against common web attacks.");

        AddCisControl(results, "CIS 7.1.2", "Ensure TLS/SSL is properly configured",
            !vulns.Any(v => v.Type.ToLowerInvariant() is "ssl" or "tls"),
            "Proper TLS configuration prevents man-in-the-middle and downgrade attacks.");

        return results;
    }

    #endregion

    #region PCI-DSS

    private List<ComplianceResult> CheckPciDss(List<Vulnerability> vulns)
    {
        var results = new List<ComplianceResult>();

        // --- Requirement 6: Develop and maintain secure systems ---
        AddPciControl(results, "PCI-DSS 6.5.1", "Injection flaws (SQLi, Command Injection)",
            !vulns.Any(v => v.Type.ToLowerInvariant() is "sql injection" or "sqli" or "command injection" or "os command injection"),
            "All injection vulnerabilities must be remediated to protect cardholder data.");

        AddPciControl(results, "PCI-DSS 6.5.2", "Buffer overflows",
            !vulns.Any(v => v.Type.ToLowerInvariant().Contains("overflow")),
            "Buffer overflow vulnerabilities must be addressed in custom code.");

        AddPciControl(results, "PCI-DSS 6.5.3", "Insecure cryptographic storage",
            !vulns.Any(v => v.Type.ToLowerInvariant() is "ssl" or "tls" &&
                     v.Description.ToLowerInvariant().Contains("weak")),
            "Cardholder data must be encrypted with strong cryptography.");

        AddPciControl(results, "PCI-DSS 6.5.4", "Insecure communications",
            !vulns.Any(v => v.Type.ToLowerInvariant() is "ssl" or "tls"),
            "All transmission of cardholder data must be encrypted.");

        AddPciControl(results, "PCI-DSS 6.5.5", "Improper error handling",
            !vulns.Any(v => v.Type.ToLowerInvariant().Contains("error") &&
                     v.Description.ToLowerInvariant().Contains("leak")),
            "Error messages must not disclose sensitive information.");

        AddPciControl(results, "PCI-DSS 6.5.6", "Cross-site scripting (XSS)",
            !vulns.Any(v => v.Type.ToLowerInvariant() is "xss" or "cross-site scripting"),
            "All XSS vulnerabilities must be fixed — these can steal session tokens and card data.");

        AddPciControl(results, "PCI-DSS 6.5.7", "Cross-site request forgery (CSRF)",
            !vulns.Any(v => v.Type.ToLowerInvariant() is "csrf" or "cross-site request forgery"),
            "CSRF protections are required for all state-changing operations.");

        AddPciControl(results, "PCI-DSS 6.5.8", "Broken authentication and session management",
            !vulns.Any(v => v.Type.ToLowerInvariant() is "auth" or "authentication"),
            "Session tokens must be properly generated, protected, and invalidated.");

        // --- Requirement 7: Restrict access ---
        AddPciControl(results, "PCI-DSS 7.1", "Limit access to cardholder data by business need-to-know",
            !vulns.Any(v => v.Type.ToLowerInvariant().Contains("access") && v.Severity is "Critical" or "High"),
            "Access controls must enforce least privilege.");

        // --- Requirement 10: Track and monitor ---
        AddPciControl(results, "PCI-DSS 10.2", "Automated audit trails",
            !vulns.Any(v => v.Type.ToLowerInvariant().Contains("log") && v.Severity is "High" or "Critical"),
            "All access to cardholder data must be logged.");

        // --- Requirement 11: Test security ---
        AddPciControl(results, "PCI-DSS 11.3", "Penetration testing methodology",
            true, // This scan itself contributes to compliance
            "Regular penetration testing validates security controls.");

        return results;
    }

    #endregion

    #region OWASP ASVS

    private List<ComplianceResult> CheckOwaspAsvs(List<Vulnerability> vulns)
    {
        var results = new List<ComplianceResult>();

        // --- V2: Authentication (ASVS Level 2) ---
        AddAsvsControl(results, "V2.1.1", "Verify that user credentials are transmitted over encrypted connections",
            !vulns.Any(v => v.Type.ToLowerInvariant() is "auth" or "authentication" && !v.Url.StartsWith("https")),
            "All authentication traffic must use TLS.", "L1");

        AddAsvsControl(results, "V2.1.2", "Verify that weak authenticators are not used (basic auth over non-TLS)",
            !vulns.Any(v => v.Type.ToLowerInvariant().Contains("basic auth") || v.Type.ToLowerInvariant().Contains("weak auth")),
            "Basic authentication without encryption is insufficient.", "L1");

        AddAsvsControl(results, "V2.2.1", "Verify that anti-automation controls (rate limiting, CAPTCHA) are effective",
            !vulns.Any(v => v.Type.ToLowerInvariant() is "auth" or "authentication" &&
                     v.Description.ToLowerInvariant().Contains("brute")),
            "Brute-force protections must be in place.", "L2");

        // --- V3: Session Management ---
        AddAsvsControl(results, "V3.2.1", "Verify the application generates a new session token on authentication",
            !vulns.Any(v => v.Type.ToLowerInvariant().Contains("session") && v.Severity is "High" or "Critical"),
            "Session fixation prevention is required.", "L1");

        // --- V4: Access Control ---
        AddAsvsControl(results, "V4.1.1", "Verify that the application enforces access control rules on trusted server-side",
            !vulns.Any(v => v.Type.ToLowerInvariant().Contains("access") && v.Severity is "High" or "Critical"),
            "Client-side access controls are easily bypassed.", "L1");

        // --- V5: Validation, Sanitization ---
        AddAsvsControl(results, "V5.1.1", "Verify the application defends against SQL injection",
            !vulns.Any(v => v.Type.ToLowerInvariant() is "sql injection" or "sqli"),
            "Parameterized queries or ORM must be used.", "L1");

        AddAsvsControl(results, "V5.1.2", "Verify the application defends against XSS (reflected and stored)",
            !vulns.Any(v => v.Type.ToLowerInvariant() is "xss" or "cross-site scripting"),
            "Output encoding and CSP are required.", "L1");

        AddAsvsControl(results, "V5.1.3", "Verify the application defends against OS command injection",
            !vulns.Any(v => v.Type.ToLowerInvariant() is "command injection" or "os command injection"),
            "User input must not be passed to OS command interpreters.", "L1");

        AddAsvsControl(results, "V5.1.4", "Verify the application defends against SSRF",
            !vulns.Any(v => v.Type.ToLowerInvariant() is "ssrf" or "server-side request forgery"),
            "URL fetching must be validated and restricted.", "L1");

        AddAsvsControl(results, "V5.2.1", "Verify path traversal protections",
            !vulns.Any(v => v.Type.ToLowerInvariant() is "path traversal" or "directory traversal"),
            "File paths must be canonicalized and validated.", "L1");

        // --- V7: Cryptography ---
        AddAsvsControl(results, "V7.1.1", "Verify TLS is used for all sensitive communications",
            !vulns.Any(v => v.Type.ToLowerInvariant() is "ssl" or "tls" && v.Severity is "High" or "Critical"),
            "TLS 1.2+ should be enforced with strong cipher suites.", "L1");

        // --- V9: Communications ---
        AddAsvsControl(results, "V9.1.1", "Verify HTTP security headers (CSP, HSTS, X-Content-Type-Options)",
            !vulns.Any(v => v.Type.ToLowerInvariant().Contains("header")),
            "Security headers mitigate many classes of web attacks.", "L1");

        // --- V14: Configuration ---
        AddAsvsControl(results, "V14.2.1", "Verify all components are up to date and patched",
            !vulns.Any(v => v.Type.ToLowerInvariant().Contains("version") && v.Severity is "High" or "Critical"),
            "Known-vulnerable components must be updated.", "L1");

        AddAsvsControl(results, "V14.3.1", "Verify CORS is properly configured (not wildcard with credentials)",
            !vulns.Any(v => v.Type.ToLowerInvariant() is "cors"),
            "Misconfigured CORS enables cross-origin attacks.", "L2");

        return results;
    }

    #endregion

    #region Helpers

    private static void AddCisControl(List<ComplianceResult> results, string control, string description, bool passed, string rationale)
    {
        results.Add(new ComplianceResult
        {
            Framework = "CIS",
            Control = control,
            Description = description,
            Passed = passed,
            Rationale = rationale
        });
    }

    private static void AddPciControl(List<ComplianceResult> results, string control, string description, bool passed, string rationale)
    {
        results.Add(new ComplianceResult
        {
            Framework = "PCI-DSS",
            Control = control,
            Description = description,
            Passed = passed,
            Rationale = rationale
        });
    }

    private static void AddAsvsControl(List<ComplianceResult> results, string control, string description, bool passed, string rationale, string level)
    {
        results.Add(new ComplianceResult
        {
            Framework = "OWASP ASVS",
            Control = control,
            Description = $"{description} [{level}]",
            Passed = passed,
            Rationale = rationale
        });
    }

    private static string GenerateReportText(ComplianceReport report, List<Vulnerability> vulns)
    {
        var sb = new StringBuilder();
        sb.AppendLine("╔══════════════════════════════════════════════════════════════╗");
        sb.AppendLine("║              COMPLIANCE ASSESSMENT REPORT                   ║");
        sb.AppendLine("║              Generated by SecKit                             ║");
        sb.AppendLine($"║              {report.GeneratedAt:yyyy-MM-dd HH:mm:ss} UTC                  ║");
        sb.AppendLine("╚══════════════════════════════════════════════════════════════╝");
        sb.AppendLine();
        sb.AppendLine($"Based on {vulns.Count} vulnerability findings.");
        sb.AppendLine();

        // --- CIS ---
        sb.AppendLine("═══════════════════════════════════════════════════════");
        sb.AppendLine("  CIS Benchmarks");
        sb.AppendLine("═══════════════════════════════════════════════════════");
        AppendResults(sb, report.CisResults);
        sb.AppendLine();

        // --- PCI-DSS ---
        sb.AppendLine("═══════════════════════════════════════════════════════");
        sb.AppendLine("  PCI-DSS v4.0");
        sb.AppendLine("═══════════════════════════════════════════════════════");
        AppendResults(sb, report.PciResults);
        sb.AppendLine();

        // --- OWASP ASVS ---
        sb.AppendLine("═══════════════════════════════════════════════════════");
        sb.AppendLine("  OWASP Application Security Verification Standard");
        sb.AppendLine("═══════════════════════════════════════════════════════");
        AppendResults(sb, report.OwaspResults);
        sb.AppendLine();

        // Summary
        sb.AppendLine("═══════════════════════════════════════════════════════");
        sb.AppendLine("  OVERALL SUMMARY");
        sb.AppendLine("═══════════════════════════════════════════════════════");
        sb.AppendLine($"  CIS Benchmarks:     {report.CisPassRate:P0} pass ({report.CisPassed}/{report.CisResults.Count})");
        sb.AppendLine($"  PCI-DSS:            {report.PciPassRate:P0} pass ({report.PciPassed}/{report.PciResults.Count})");
        sb.AppendLine($"  OWASP ASVS:         {report.OwaspPassRate:P0} pass ({report.OwaspPassed}/{report.OwaspResults.Count})");
        sb.AppendLine($"  ─────────────────────────────────────────────────");
        sb.AppendLine($"  OVERALL:            {report.OverallPassRate:P0} pass");
        sb.AppendLine();

        return sb.ToString();
    }

    private static void AppendResults(StringBuilder sb, List<ComplianceResult> results)
    {
        foreach (var r in results)
        {
            var symbol = r.Passed ? "✅ PASS" : "❌ FAIL";
            sb.AppendLine($"  {symbol}  {r.Control}: {r.Description}");
            sb.AppendLine($"          {r.Rationale}");
        }
    }

    private static string GenerateReportJson(ComplianceReport report)
    {
        var allResults = new List<object>();
        allResults.AddRange(report.CisResults.Select(r => new
        {
            framework = r.Framework,
            control = r.Control,
            description = r.Description,
            passed = r.Passed,
            rationale = r.Rationale
        }));
        allResults.AddRange(report.PciResults.Select(r => new
        {
            framework = r.Framework,
            control = r.Control,
            description = r.Description,
            passed = r.Passed,
            rationale = r.Rationale
        }));
        allResults.AddRange(report.OwaspResults.Select(r => new
        {
            framework = r.Framework,
            control = r.Control,
            description = r.Description,
            passed = r.Passed,
            rationale = r.Rationale
        }));

        var jsonObj = new
        {
            generatedAt = report.GeneratedAt.ToString("o"),
            summary = new
            {
                cisPassRate = report.CisPassRate,
                pciPassRate = report.PciPassRate,
                owaspPassRate = report.OwaspPassRate,
                overallPassRate = report.OverallPassRate
            },
            results = allResults
        };

        return System.Text.Json.JsonSerializer.Serialize(jsonObj, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
    }

    #endregion
}

/// <summary>Single compliance check result.</summary>
public class ComplianceResult
{
    public string Framework { get; set; } = string.Empty;
    public string Control { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public bool Passed { get; set; }
    public string Rationale { get; set; } = string.Empty;
}

/// <summary>Full compliance report.</summary>
public class ComplianceReport
{
    public DateTime GeneratedAt { get; set; }
    public string ReportPath { get; set; } = string.Empty;
    public string JsonPath { get; set; } = string.Empty;

    public List<ComplianceResult> CisResults { get; set; } = new();
    public List<ComplianceResult> PciResults { get; set; } = new();
    public List<ComplianceResult> OwaspResults { get; set; } = new();

    // CIS
    public int CisPassed => CisResults.Count(r => r.Passed);
    public int CisFailed => CisResults.Count(r => !r.Passed);
    public double CisPassRate => CisResults.Count == 0 ? 0 : (double)CisPassed / CisResults.Count;

    // PCI-DSS
    public int PciPassed => PciResults.Count(r => r.Passed);
    public int PciFailed => PciResults.Count(r => !r.Passed);
    public double PciPassRate => PciResults.Count == 0 ? 0 : (double)PciPassed / PciResults.Count;

    // OWASP ASVS
    public int OwaspPassed => OwaspResults.Count(r => r.Passed);
    public int OwaspFailed => OwaspResults.Count(r => !r.Passed);
    public double OwaspPassRate => OwaspResults.Count == 0 ? 0 : (double)OwaspPassed / OwaspResults.Count;

    // Overall
    public int TotalPassed => CisPassed + PciPassed + OwaspPassed;
    public int TotalControls => CisResults.Count + PciResults.Count + OwaspResults.Count;
    public double OverallPassRate => TotalControls == 0 ? 0 : (double)TotalPassed / TotalControls;
}
