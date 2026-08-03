using System.Text.RegularExpressions;
using SecKit.Core;
using SecKit.Models;

namespace SecKit.Modules.RedTeam;

/// <summary>
/// Scans web endpoints for CORS misconfigurations by sending cross-origin requests
/// with various Origin header values. Tests null origins, subdomain reflection,
/// prefix/post-domain spoofing, wildcard origins, and wildcard-with-credentials combinations.
/// </summary>
public class CorsScanner
{
    private readonly HttpClient _client;
    private readonly ConfigManager _config;

    // Test origins to probe with
    private static readonly (string Origin, string Label)[] TestOrigins =
    {
        ("null", "Null origin"),
        ("https://evil.example.com", "Random origin"),
        ("https://attacker.com", "Attacker origin"),
        ("http://localhost", "Localhost origin"),
        ("http://127.0.0.1", "Loopback IP origin"),
        ("https://evil.com", "Malicious origin"),
    };

    // Sensitive headers to check for in ACAH (Access-Control-Allow-Headers)
    private static readonly string[] SensitiveAllowHeaders =
    {
        "Authorization", "X-Auth-Token", "Cookie", "X-CSRF-Token",
        "X-API-Key", "X-Requested-With", "X-HTTP-Method-Override"
    };

    public CorsScanner(HttpClient client, ConfigManager config)
    {
        _client = client;
        _config = config;
    }

    /// <summary>Scans a target URL for CORS misconfigurations.</summary>
    public async Task<ScanResult> ScanAsync(string target)
    {
        var result = new ScanResult
        {
            ModuleName = "CORS Scanner",
            TargetUrl = target,
            StartTime = DateTime.UtcNow
        };

        try
        {
            // Phase 1: Test with standard origins
            foreach (var (origin, label) in TestOrigins)
            {
                result.RequestsSent++;
                await TestOriginAsync(result, target, origin, label);
            }

            // Phase 2: Test subdomain / suffix reflection
            result.RequestsSent++;
            await TestSubdomainReflectionAsync(result, target);

            // Phase 3: Test OPTIONS preflight
            result.RequestsSent++;
            await TestPreflightAsync(result, target);

            result.EndpointsTested = 1;
            result.Completed = true;
        }
        catch (Exception ex)
        {
            result.ErrorMessage = ex.Message;
            Logger.Error($"CORS Scanner failed: {ex.Message}");
        }

        result.EndTime = DateTime.UtcNow;
        return result;
    }

    private async Task TestOriginAsync(ScanResult result, string targetUrl, string origin, string label)
    {
        try
        {
            var request = new HttpRequestMessage(HttpMethod.Get, targetUrl);
            request.Headers.TryAddWithoutValidation("Origin", origin);

            var response = await _client.SendAsync(request);
            var acao = response.Headers.Contains("Access-Control-Allow-Origin")
                ? string.Join(", ", response.Headers.GetValues("Access-Control-Allow-Origin"))
                : null;
            var acac = response.Headers.Contains("Access-Control-Allow-Credentials")
                ? string.Join(", ", response.Headers.GetValues("Access-Control-Allow-Credentials"))
                : null;

            // Check: origin reflected back
            if (acao != null && acao.Equals(origin, StringComparison.OrdinalIgnoreCase))
            {
                var severity = origin == "null" ? "High" : "Medium";
                var desc = origin == "null"
                    ? "Server reflects 'null' origin — allows sandboxed/iframe requests. The null origin should never be trusted."
                    : $"Server reflects arbitrary origin '{origin}' — CORS allows any origin dynamically.";

                var id = origin == "null" ? "CORS: Null Origin Allowed" : "CORS: Origin Reflection";

                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = id,
                    Severity = severity,
                    Url = targetUrl,
                    Parameter = "Origin",
                    Payload = origin,
                    Description = desc,
                    Evidence = $"ACAO: {acao}, ACAC: {acac ?? "(not set)"}",
                    Remediation = "Use a static, whitelist-based ACAO. Never echo the Origin header back. Validate origins server-side.",
                    Module = "CorsScanner",
                    Confidence = 85
                });
                Logger.LogVulnerability(result.Vulnerabilities.Last());
            }

            // Check: wildcard ACAO
            if (acao == "*")
            {
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "CORS: Wildcard ACAO",
                    Severity = "Low",
                    Url = targetUrl,
                    Parameter = "Origin",
                    Payload = origin,
                    Description = "Server sets Access-Control-Allow-Origin: * (wildcard). All origins can read responses.",
                    Evidence = $"ACAO: *, ACAC: {acac ?? "(not set)"}",
                    Remediation = "Replace '*' with specific trusted origins.",
                    Module = "CorsScanner",
                    Confidence = 100
                });
                Logger.LogVulnerability(result.Vulnerabilities.Last());
            }

            // Check: wildcard + credentials
            if (acao == "*" && acac != null && acac.Equals("true", StringComparison.OrdinalIgnoreCase))
            {
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "CORS: Wildcard + Credentials",
                    Severity = "Critical",
                    Url = targetUrl,
                    Parameter = "Origin",
                    Payload = origin,
                    Description = "ACAO is '*' AND ACAC is 'true' — browsers will reject this combination, but it indicates a dangerous misconfiguration. If the browser doesn't enforce this, credentials are leaked to any origin.",
                    Evidence = $"ACAO: *, ACAC: true",
                    Remediation = "Credentials with wildcard origins is never valid. Use specific origins with credentials.",
                    Module = "CorsScanner",
                    Confidence = 95
                });
                Logger.LogVulnerability(result.Vulnerabilities.Last());
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"CORS test with origin '{origin}' failed: {ex.Message}");
        }
    }

    private async Task TestSubdomainReflectionAsync(ScanResult result, string targetUrl)
    {
        try
        {
            // Try to detect if the server reflects subdomain variants
            var uri = new Uri(targetUrl);
            var host = uri.Host;

            // Generate spoof origins: prefix the target domain
            var spoofOrigins = new[]
            {
                $"https://evil{host}",              // pre-domain append
                $"https://{host}.evil.com",          // post-domain append
                $"https://evil.{host}",               // pre-domain dot
                $"https://not{host}",                 // similar prefix
                $"http://{host}",                     // downgrade to HTTP
            };

            foreach (var origin in spoofOrigins)
            {
                try
                {
                    var request = new HttpRequestMessage(HttpMethod.Get, targetUrl);
                    request.Headers.TryAddWithoutValidation("Origin", origin);
                    var response = await _client.SendAsync(request);

                    if (response.Headers.TryGetValues("Access-Control-Allow-Origin", out var acaoVals))
                    {
                        var acao = acaoVals.FirstOrDefault() ?? "";
                        if (acao.Equals(origin, StringComparison.OrdinalIgnoreCase))
                        {
                            result.Vulnerabilities.Add(new Vulnerability
                            {
                                Type = "CORS: Subdomain/Post-domain Spoof",
                                Severity = "High",
                                Url = targetUrl,
                                Parameter = "Origin",
                                Payload = origin,
                                Description = $"Server reflected a spoofed origin '{origin}'. The server likely uses prefix/suffix matching that can be exploited.",
                                Evidence = $"ACAO: {acao}",
                                Remediation = "Use exact origin matching against a whitelist. Do not use substring/prefix matches.",
                                Module = "CorsScanner",
                                Confidence = 75
                            });
                            Logger.LogVulnerability(result.Vulnerabilities.Last());
                            break; // One spoof finding is enough
                        }
                    }
                }
                catch (Exception ex)
                {
                    Logger.Debug($"Subdomain spoof test failed for '{origin}': {ex.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"Subdomain reflection test failed: {ex.Message}");
        }
    }

    private async Task TestPreflightAsync(ScanResult result, string targetUrl)
    {
        try
        {
            var request = new HttpRequestMessage(HttpMethod.Options, targetUrl);
            request.Headers.TryAddWithoutValidation("Origin", "https://attacker.com");
            request.Headers.TryAddWithoutValidation("Access-Control-Request-Method", "PUT"); // non-simple method
            request.Headers.TryAddWithoutValidation("Access-Control-Request-Headers", "Authorization, X-Custom");

            var response = await _client.SendAsync(request);

            if (response.IsSuccessStatusCode)
            {
                // Check allowed methods in preflight response
                if (response.Headers.TryGetValues("Access-Control-Allow-Methods", out var methods))
                {
                    var allowedMethods = string.Join(", ", methods).ToUpperInvariant();
                    if (allowedMethods.Contains("PUT") || allowedMethods.Contains("DELETE") ||
                        allowedMethods.Contains("PATCH"))
                    {
                        result.Vulnerabilities.Add(new Vulnerability
                        {
                            Type = "CORS: Dangerous Methods Allowed",
                            Severity = "Medium",
                            Url = targetUrl,
                            Parameter = "Access-Control-Allow-Methods",
                            Payload = allowedMethods,
                            Description = $"Preflight allows state-changing HTTP methods: {allowedMethods}. Cross-origin requests can modify resources.",
                            Evidence = $"ACAM: {allowedMethods}",
                            Remediation = "Restrict allowed methods to GET and POST only unless explicitly needed for a CORS endpoint.",
                            Module = "CorsScanner",
                            Confidence = 70
                        });
                        Logger.LogVulnerability(result.Vulnerabilities.Last());
                    }

                    // Check for wildcard methods
                    if (allowedMethods.Contains("*"))
                    {
                        result.Vulnerabilities.Add(new Vulnerability
                        {
                            Type = "CORS: Wildcard Methods",
                            Severity = "Medium",
                            Url = targetUrl,
                            Parameter = "Access-Control-Allow-Methods",
                            Payload = "*",
                            Description = "Preflight response allows all HTTP methods with wildcard '*'.",
                            Evidence = $"ACAM: *",
                            Remediation = "Specify exact allowed methods instead of wildcard.",
                            Module = "CorsScanner",
                            Confidence = 90
                        });
                        Logger.LogVulnerability(result.Vulnerabilities.Last());
                    }
                }

                // Check allowed headers
                if (response.Headers.TryGetValues("Access-Control-Allow-Headers", out var headers))
                {
                    var allowedHeaders = string.Join(", ", headers);
                    foreach (var sensitive in SensitiveAllowHeaders)
                    {
                        if (allowedHeaders.Contains(sensitive, StringComparison.OrdinalIgnoreCase))
                        {
                            result.Vulnerabilities.Add(new Vulnerability
                            {
                                Type = "CORS: Sensitive Header Allowed",
                                Severity = "Medium",
                                Url = targetUrl,
                                Parameter = "Access-Control-Allow-Headers",
                                Payload = sensitive,
                                Description = $"Preflight allows sensitive header '{sensitive}' — cross-origin requests can include auth tokens.",
                                Evidence = $"ACAH: {allowedHeaders}",
                                Remediation = $"Remove '{sensitive}' from allowed headers unless absolutely required.",
                                Module = "CorsScanner",
                                Confidence = 70
                            });
                            Logger.LogVulnerability(result.Vulnerabilities.Last());
                        }
                    }
                }

                // Check Max-Age (long preflight caching)
                if (response.Headers.TryGetValues("Access-Control-Max-Age", out var maxAgeVals) &&
                    int.TryParse(maxAgeVals.FirstOrDefault(), out var maxAge) && maxAge > 3600)
                {
                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = "CORS: Long Preflight Cache",
                        Severity = "Low",
                        Url = targetUrl,
                        Parameter = "Access-Control-Max-Age",
                        Payload = maxAge.ToString(),
                        Description = $"Preflight results are cached for {maxAge} seconds. Changes to CORS policy won't take effect quickly.",
                        Evidence = $"ACMA: {maxAge}",
                        Remediation = "Reduce Access-Control-Max-Age to a reasonable value (≤ 600 seconds).",
                        Module = "CorsScanner",
                        Confidence = 60
                    });
                    Logger.LogVulnerability(result.Vulnerabilities.Last());
                }
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"Preflight test failed: {ex.Message}");
        }
    }
}
