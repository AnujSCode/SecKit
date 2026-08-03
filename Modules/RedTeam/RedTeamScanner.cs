using SecKit.Core;
using SecKit.Models;

namespace SecKit.Modules.RedTeam;

/// <summary>
/// Red Team tools — JWT analysis, CORS misconfiguration, credential testing, GraphQL introspection.
/// </summary>
public class RedTeamScanner
{
    private readonly HttpClient _httpClient;
    private readonly ConfigManager _config;

    public RedTeamScanner(HttpClient httpClient, ConfigManager config)
    {
        _httpClient = httpClient;
        _config = config;
    }

    public async Task<ScanResult> ScanAllAsync(string url)
    {
        var result = new ScanResult
        {
            ModuleName = "Red Team Tools",
            TargetUrl = url,
            StartTime = DateTime.UtcNow,
            Completed = true
        };

        result.Vulnerabilities.AddRange(await TestJwtAsync(url));
        result.Vulnerabilities.AddRange(await TestCorsAsync(url));
        result.Vulnerabilities.AddRange(await TestCredentialsAsync(url));
        result.Vulnerabilities.AddRange(await TestGraphQlAsync(url));

        result.EndTime = DateTime.UtcNow;
        return result;
    }

    public async Task<List<Vulnerability>> TestJwtAsync(string url)
    {
        var vulns = new List<Vulnerability>();
        try
        {
            var response = await _httpClient.GetAsync(url);
            foreach (var cookie in response.Headers.GetValues("Set-Cookie"))
            {
                if (cookie.Contains("jwt") || cookie.Contains("token=") || cookie.Contains("Bearer"))
                {
                    // Check JWT for common weaknesses
                    var parts = cookie.Split('.');
                    if (parts.Length == 3)
                    {
                        vulns.Add(new Vulnerability
                        {
                            Type = "JWT Analysis",
                            Severity = "Medium",
                            Url = url,
                            Parameter = "Authorization",
                            Description = "JWT token detected in cookie. Verify: HS256 not used with known secrets, 'none' algorithm rejected, proper expiration set, no sensitive data in payload.",
                            Remediation = "Use RS256/ES256, validate algorithm, set short expiration, use refresh tokens.",
                            Evidence = $"JWT header: {parts[0][..Math.Min(parts[0].Length, 50)]}...",
                            Module = "RedTeam",
                            Confidence = 70
                        });
                    }
                }
            }

            if (vulns.Count == 0)
            {
                vulns.Add(new Vulnerability
                {
                    Type = "JWT Analysis",
                    Severity = "Info",
                    Url = url,
                    Description = "No JWT tokens detected in response cookies/headers.",
                    Module = "RedTeam"
                });
            }
        }
        catch (Exception ex)
        {
            vulns.Add(new Vulnerability
            {
                Type = "JWT Analysis",
                Severity = "Info",
                Url = url,
                Description = $"Could not analyze JWT: {ex.Message}",
                Module = "RedTeam"
            });
        }
        return vulns;
    }

    public async Task<List<Vulnerability>> TestCorsAsync(string url)
    {
        var vulns = new List<Vulnerability>();
        try
        {
            var request = new HttpRequestMessage(HttpMethod.Options, url);
            request.Headers.Add("Origin", "https://evil.com");
            request.Headers.Add("Access-Control-Request-Method", "GET");

            var response = await _httpClient.SendAsync(request);

            if (response.Headers.Contains("Access-Control-Allow-Origin"))
            {
                var acao = response.Headers.GetValues("Access-Control-Allow-Origin").FirstOrDefault();
                if (acao == "*" || acao == "https://evil.com")
                {
                    bool hasCredentials = response.Headers.Contains("Access-Control-Allow-Credentials") &&
                        response.Headers.GetValues("Access-Control-Allow-Credentials").FirstOrDefault() == "true";

                    vulns.Add(new Vulnerability
                    {
                        Type = "CORS Misconfiguration",
                        Severity = hasCredentials ? "High" : "Medium",
                        Url = url,
                        Parameter = "Access-Control-Allow-Origin",
                        Description = $"CORS allows origin: {acao}{(hasCredentials ? " WITH credentials — critical misconfiguration!" : "")}",
                        Remediation = "Restrict CORS to specific trusted origins. Never use '*' with credentials.",
                        Evidence = $"ACAO: {acao}, ACAC: {(hasCredentials ? "true" : "not set")}",
                        Module = "RedTeam",
                        Confidence = 85
                    });
                }
                else
                {
                    vulns.Add(new Vulnerability
                    {
                        Type = "CORS Configuration",
                        Severity = "Info",
                        Url = url,
                        Description = $"CORS header present: {acao} (not vulnerable to arbitrary origin reflection)",
                        Module = "RedTeam"
                    });
                }
            }
            else
            {
                vulns.Add(new Vulnerability
                {
                    Type = "CORS Configuration",
                    Severity = "Info",
                    Url = url,
                    Description = "No CORS headers in response (same-origin policy enforced).",
                    Module = "RedTeam"
                });
            }
        }
        catch (Exception ex)
        {
            vulns.Add(new Vulnerability
            {
                Type = "CORS Test",
                Severity = "Info",
                Url = url,
                Description = $"CORS test skipped: {ex.Message}",
                Module = "RedTeam"
            });
        }
        return vulns;
    }

    public async Task<List<Vulnerability>> TestCredentialsAsync(string url)
    {
        var vulns = new List<Vulnerability>();
        try
        {
            // Test common credential endpoints
            var loginPaths = new[] { "/login", "/auth", "/signin", "/api/login", "/admin/login" };
            var weakCredentials = new Dictionary<string, string>
            {
                ["admin"] = "admin",
                ["admin"] = "password",
                ["root"] = "root",
                ["test"] = "test",
                ["user"] = "password"
            };

            foreach (var path in loginPaths)
            {
                try
                {
                    var loginUrl = new Uri(new Uri(url), path).ToString();
                    var content = new FormUrlEncodedContent(weakCredentials.Take(1).Select(kv =>
                        new KeyValuePair<string, string>("username", kv.Key)).Concat(
                        weakCredentials.Take(1).Select(kv =>
                        new KeyValuePair<string, string>("password", kv.Value))));

                    var response = await _httpClient.PostAsync(loginUrl, content);
                    if (response.IsSuccessStatusCode && !response.RequestMessage!.RequestUri!.ToString().Contains("login"))
                    {
                        vulns.Add(new Vulnerability
                        {
                            Type = "Weak Credentials",
                            Severity = "Critical",
                            Url = loginUrl,
                            Description = "Login endpoint accepted common/default credentials.",
                            Remediation = "Enforce strong password policy and disable default accounts.",
                            Module = "RedTeam",
                            Confidence = 80
                        });
                    }
                }
                catch { /* endpoint may not exist */ }
            }

            if (vulns.Count == 0)
            {
                vulns.Add(new Vulnerability
                {
                    Type = "Credential Testing",
                    Severity = "Info",
                    Url = url,
                    Description = "Tested common login endpoints — no weak credentials detected (or endpoints not found).",
                    Module = "RedTeam"
                });
            }
        }
        catch (Exception ex)
        {
            vulns.Add(new Vulnerability
            {
                Type = "Credential Testing",
                Severity = "Info",
                Url = url,
                Description = $"Credential test limited: {ex.Message}",
                Module = "RedTeam"
            });
        }
        return vulns;
    }

    public async Task<List<Vulnerability>> TestGraphQlAsync(string url)
    {
        var vulns = new List<Vulnerability>();
        try
        {
            var graphqlPaths = new[] { "/graphql", "/api/graphql", "/gql", "/query" };

            foreach (var path in graphqlPaths)
            {
                try
                {
                    var gqlUrl = new Uri(new Uri(url), path).ToString();

                    // Test introspection
                    var introspectionQuery = "{\"query\":\"{__schema{types{name}}}\"}";
                    var content = new StringContent(introspectionQuery, System.Text.Encoding.UTF8, "application/json");
                    var response = await _httpClient.PostAsync(gqlUrl, content);

                    var body = await response.Content.ReadAsStringAsync();
                    if (body.Contains("__schema") || body.Contains("\"types\""))
                    {
                        vulns.Add(new Vulnerability
                        {
                            Type = "GraphQL Introspection",
                            Severity = "Medium",
                            Url = gqlUrl,
                            Description = "GraphQL introspection is enabled — exposes entire schema to attackers.",
                            Remediation = "Disable introspection in production or restrict to authenticated admin users.",
                            Evidence = body[..Math.Min(body.Length, 200)],
                            Module = "RedTeam",
                            Confidence = 90
                        });
                        break;
                    }
                }
                catch { /* path may not exist */ }
            }

            if (vulns.Count == 0)
            {
                vulns.Add(new Vulnerability
                {
                    Type = "GraphQL Analysis",
                    Severity = "Info",
                    Url = url,
                    Description = "No GraphQL endpoints found with introspection enabled (or no GraphQL endpoints detected).",
                    Module = "RedTeam"
                });
            }
        }
        catch (Exception ex)
        {
            vulns.Add(new Vulnerability
            {
                Type = "GraphQL Analysis",
                Severity = "Info",
                Url = url,
                Description = $"GraphQL test skipped: {ex.Message}",
                Module = "RedTeam"
            });
        }
        return vulns;
    }
}
