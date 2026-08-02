using System.Net;
using SecKit.Core;
using SecKit.Models;

namespace SecKit.Modules.NetworkScanner;

/// <summary>Analyzes HTTP response headers for security best practices.</summary>
public class HeaderAnalyzer
{
    private readonly HttpClient _client;
    private readonly ConfigManager _config;

    private static readonly (string Header, string Description, string Remediation, int ScoreWeight)[] RequiredHeaders =
    {
        ("Content-Security-Policy", "CSP prevents XSS, clickjacking, and code injection attacks.", "Define a strict CSP: default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'", 25),
        ("X-Frame-Options", "Prevents clickjacking by controlling iframe embedding.", "Set X-Frame-Options: DENY or SAMEORIGIN", 15),
        ("X-Content-Type-Options", "Prevents MIME type sniffing.", "Set X-Content-Type-Options: nosniff", 10),
        ("Referrer-Policy", "Controls how much referrer information is sent.", "Set Referrer-Policy: strict-origin-when-cross-origin", 10),
        ("Permissions-Policy", "Controls which browser features can be used.", "Define a restrictive Permissions-Policy header", 10),
        ("Strict-Transport-Security", "Enforces HTTPS connections.", "Set Strict-Transport-Security: max-age=31536000; includeSubDomains", 15),
    };

    private static readonly (string Header, string Description)[] AdditionalChecks =
    {
        ("X-XSS-Protection", "Legacy XSS filter. Should be set to '0' when CSP is used, or '1; mode=block'."),
        ("X-Permitted-Cross-Domain-Policies", "Controls cross-domain policies for Flash/PDF."),
        ("Cross-Origin-Resource-Policy", "Controls which origins can load resources."),
        ("Cross-Origin-Opener-Policy", "Process isolation for cross-origin windows."),
        ("Cross-Origin-Embedder-Policy", "Controls embedding of cross-origin resources."),
        ("Cache-Control", "Controls caching behavior."),
        ("Clear-Site-Data", "Clears browsing data on response."),
        ("Server", "Server banner — revealing version info may aid attackers."),
        ("X-Powered-By", "Technology banner — may reveal framework version info."),
        ("X-AspNet-Version", "ASP.NET version banner — reveals framework version."),
    };

    public HeaderAnalyzer(HttpClient client, ConfigManager config)
    {
        _client = client;
        _config = config;
    }

    /// <summary>Analyzes security headers on a target URL and provides a security grade.</summary>
    public async Task<ScanResult> AnalyzeAsync(string targetUrl)
    {
        var result = new ScanResult
        {
            ModuleName = "Header Analyzer",
            TargetUrl = targetUrl,
            StartTime = DateTime.UtcNow
        };

        try
        {
            result.EndpointsTested = 1;
            var response = await _client.GetAsync(targetUrl);
            result.RequestsSent++;

            Logger.WriteLine($"\n📋 Security Header Analysis for {targetUrl}", ConsoleColor.Cyan);
            Logger.WriteLine(new string('─', 60), ConsoleColor.Gray);

            var totalScore = 100;
            var missingHeaders = 0;

            // Check required security headers
            foreach (var (header, description, remediation, scoreWeight) in RequiredHeaders)
            {
                if (response.Headers.Contains(header) ||
                    response.Content.Headers.Contains(header))
                {
                    var value = GetHeaderValue(response, header);
                    Logger.WriteLine($"  ✓ {header}", ConsoleColor.Green);
                    Logger.WriteLine($"      Value: {Truncate(value, 80)}", ConsoleColor.Gray);

                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = $"Security Header Present: {header}",
                        Severity = "Info",
                        Url = targetUrl,
                        Parameter = header,
                        Payload = value,
                        Description = description,
                        Remediation = remediation,
                        Module = "HeaderAnalyzer",
                        Confidence = 100
                    });
                }
                else
                {
                    totalScore -= scoreWeight;
                    missingHeaders++;

                    var severity = header switch
                    {
                        "Content-Security-Policy" => "High",
                        "Strict-Transport-Security" => "High",
                        "X-Frame-Options" => "Medium",
                        "X-Content-Type-Options" => "Medium",
                        _ => "Low"
                    };

                    Logger.WriteLine($"  ✗ {header} MISSING", ConsoleColor.Red);

                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = $"Missing Security Header: {header}",
                        Severity = severity,
                        Url = targetUrl,
                        Parameter = header,
                        Description = $"Security header '{header}' is not set. {description}",
                        Remediation = remediation,
                        Module = "HeaderAnalyzer",
                        Confidence = 100
                    });
                }
            }

            // Check additional headers
            foreach (var (header, description) in AdditionalChecks)
            {
                if (response.Headers.Contains(header) ||
                    response.Content.Headers.Contains(header))
                {
                    var value = GetHeaderValue(response, header);

                    if (header == "Server" || header == "X-Powered-By" || header == "X-AspNet-Version")
                    {
                        // Banner disclosure is a finding
                        Logger.WriteLine($"  ⚠ {header}: {value}", ConsoleColor.Yellow);
                        result.Vulnerabilities.Add(new Vulnerability
                        {
                            Type = "Information Disclosure",
                            Severity = "Low",
                            Url = targetUrl,
                            Parameter = header,
                            Payload = value,
                            Description = $"Server banner reveals: {value}. Attackers can use version info to target known exploits.",
                            Remediation = "Remove or obfuscate server/technology banners in production.",
                            Module = "HeaderAnalyzer",
                            Confidence = 100
                        });
                    }
                    else
                    {
                        Logger.WriteLine($"  ✓ {header}: {Truncate(value, 60)}", ConsoleColor.DarkGreen);
                    }
                }
            }

            // Check cookies
            if (response.Headers.Contains("Set-Cookie"))
            {
                var cookies = response.Headers.GetValues("Set-Cookie");
                foreach (var cookie in cookies)
                {
                    if (!cookie.Contains("HttpOnly", StringComparison.OrdinalIgnoreCase))
                    {
                        result.Vulnerabilities.Add(new Vulnerability
                        {
                            Type = "Cookie Missing HttpOnly",
                            Severity = "Medium",
                            Url = targetUrl,
                            Parameter = "Set-Cookie",
                            Payload = cookie,
                            Description = "Cookie does not have HttpOnly flag.",
                            Remediation = "Add HttpOnly flag to all cookies.",
                            Module = "HeaderAnalyzer",
                            Confidence = 95
                        });
                    }
                    if (!cookie.Contains("Secure", StringComparison.OrdinalIgnoreCase) && targetUrl.StartsWith("https://"))
                    {
                        result.Vulnerabilities.Add(new Vulnerability
                        {
                            Type = "Cookie Missing Secure Flag",
                            Severity = "High",
                            Url = targetUrl,
                            Parameter = "Set-Cookie",
                            Payload = cookie,
                            Description = "Cookie missing Secure flag on HTTPS site.",
                            Remediation = "Add Secure flag to all cookies served over HTTPS.",
                            Module = "HeaderAnalyzer",
                            Confidence = 95
                        });
                    }
                    if (!cookie.Contains("SameSite", StringComparison.OrdinalIgnoreCase))
                    {
                        result.Vulnerabilities.Add(new Vulnerability
                        {
                            Type = "Cookie Missing SameSite",
                            Severity = "Low",
                            Url = targetUrl,
                            Parameter = "Set-Cookie",
                            Payload = cookie,
                            Description = "Cookie missing SameSite attribute.",
                            Remediation = "Set SameSite=Lax or SameSite=Strict on cookies.",
                            Module = "HeaderAnalyzer",
                            Confidence = 85
                        });
                    }
                }
            }

            // Print grade
            var grade = totalScore switch
            {
                >= 90 => "A",
                >= 75 => "B",
                >= 60 => "C",
                >= 40 => "D",
                _ => "F"
            };
            var gradeColor = grade switch { "A" => ConsoleColor.Green, "B" => ConsoleColor.DarkGreen, "C" => ConsoleColor.Yellow, _ => ConsoleColor.Red };

            Logger.WriteLine($"\n  Grade: {grade} ({totalScore}/100)", gradeColor);
            Logger.WriteLine(new string('─', 60), ConsoleColor.Gray);

            result.Completed = true;
        }
        catch (Exception ex)
        {
            result.ErrorMessage = ex.Message;
            Logger.Error($"Header analyzer failed: {ex.Message}");
        }

        result.EndTime = DateTime.UtcNow;
        return result;
    }

    private static string GetHeaderValue(HttpResponseMessage response, string header)
    {
        if (response.Headers.TryGetValues(header, out var values))
            return string.Join(", ", values);
        if (response.Content.Headers.TryGetValues(header, out var contentValues))
            return string.Join(", ", contentValues);
        return "present";
    }

    private static string Truncate(string value, int maxLength) =>
        value.Length > maxLength ? value[..maxLength] + "..." : value;
}
