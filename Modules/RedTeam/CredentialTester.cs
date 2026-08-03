using System.Collections.Concurrent;
using System.Net;
using System.Text.RegularExpressions;
using SecKit.Core;
using SecKit.Models;

namespace SecKit.Modules.RedTeam;

/// <summary>
/// Tests login endpoints for weak credentials, account lockout behavior,
/// and username enumeration vulnerabilities. Rate-limited to avoid lockouts.
/// </summary>
public class CredentialTester
{
    private readonly HttpClient _client;
    private readonly ConfigManager _config;
    private readonly Random _rng = new();

    // Common weak credentials to test
    private static readonly (string User, string Pass)[] WeakCredentials =
    {
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "admin123"),
        ("admin", "123456"),
        ("admin", "passw0rd"),
        ("admin", "changeme"),
        ("admin", ""),
        ("root", "root"),
        ("root", "password"),
        ("root", "toor"),
        ("root", "admin"),
        ("test", "test"),
        ("test", "testing"),
        ("test", "1234"),
        ("user", "user"),
        ("user", "password"),
        ("guest", "guest"),
        ("guest", ""),
        ("administrator", "administrator"),
        ("administrator", "password"),
        ("Administrator", "Administrator"),
    };

    // Common login endpoint paths
    private static readonly string[] LoginPaths =
    {
        "/login", "/signin", "/auth/login", "/api/login",
        "/api/auth/login", "/api/v1/login", "/user/login",
        "/admin/login", "/wp-login.php", "/auth",
        "/api/authenticate", "/oauth/token", "/token",
        "/api/auth", "/auth/signin", "/account/login",
        "/sign_in", "/logon"
    };

    // Username enumeration test pairs
    private static readonly (string ValidUser, string InvalidUser)[] UserEnumPairs =
    {
        ("admin", "nonexistent_user_12345"),
        ("root", "fake_user_67890"),
        ("administrator", "no_such_user_99999"),
        ("user", "completely_fake_user_000"),
    };

    public CredentialTester(HttpClient client, ConfigManager config)
    {
        _client = client;
        _config = config;
    }

    /// <summary>Scans a target for weak credentials, lockout, and user enumeration.</summary>
    public async Task<ScanResult> ScanAsync(string target)
    {
        var result = new ScanResult
        {
            ModuleName = "Credential Tester",
            TargetUrl = target,
            StartTime = DateTime.UtcNow
        };

        try
        {
            // Phase 1: Discover login endpoint
            var loginUrl = await DiscoverLoginEndpointAsync(target);
            if (loginUrl == null)
            {
                Logger.Warning("No login endpoint discovered on target.");
                result.Completed = true;
                result.EndTime = DateTime.UtcNow;
                return result;
            }

            result.EndpointsTested = 1;
            Logger.Info($"Testing credentials against {loginUrl}...");

            // Phase 2: Test weak credentials (rate-limited)
            await TestWeakCredentialsAsync(result, loginUrl);

            // Phase 3: Test username enumeration
            await TestUsernameEnumerationAsync(result, loginUrl);

            // Phase 4: Test account lockout behavior
            await TestAccountLockoutAsync(result, loginUrl);

            result.Completed = true;
        }
        catch (Exception ex)
        {
            result.ErrorMessage = ex.Message;
            Logger.Error($"Credential Tester failed: {ex.Message}");
        }

        result.EndTime = DateTime.UtcNow;
        return result;
    }

    private async Task<string?> DiscoverLoginEndpointAsync(string target)
    {
        // Try common paths
        foreach (var path in LoginPaths)
        {
            try
            {
                var url = new Uri(new Uri(target), path).ToString();
                var response = await _client.GetAsync(url);
                var body = await response.Content.ReadAsStringAsync();

                // Look for signs of a login form
                var hasForm = body.Contains("<form", StringComparison.OrdinalIgnoreCase) &&
                    (body.Contains("password", StringComparison.OrdinalIgnoreCase) ||
                     body.Contains("passwd", StringComparison.OrdinalIgnoreCase));

                if (hasForm && response.IsSuccessStatusCode)
                {
                    Logger.Info($"Found login endpoint: {url}");
                    return url;
                }

                // Also check for API auth endpoints that return 405 on GET but 200 on POST
                if (response.StatusCode == HttpStatusCode.MethodNotAllowed)
                {
                    // This might be an API endpoint — probe with POST
                    Logger.Debug($"Found potential API login at {url} (405 on GET)");
                    return url;
                }
            }
            catch (Exception ex)
            {
                Logger.Debug($"Login discovery failed for {path}: {ex.Message}");
            }
        }

        // Fallback: check the target itself
        try
        {
            var response = await _client.GetAsync(target);
            var body = await response.Content.ReadAsStringAsync();
            if (body.Contains("<form", StringComparison.OrdinalIgnoreCase) &&
                body.Contains("password", StringComparison.OrdinalIgnoreCase))
            {
                return target;
            }
        }
        catch { }

        return null;
    }

    private async Task TestWeakCredentialsAsync(ScanResult result, string loginUrl)
    {
        var foundCredentials = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var requestDelay = TimeSpan.FromSeconds(1); // Rate limit: 1 req/sec

        foreach (var (username, password) in WeakCredentials)
        {
            try
            {
                result.RequestsSent++;
                var formData = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("username", username),
                    new KeyValuePair<string, string>("password", password),
                    new KeyValuePair<string, string>("email", username),
                });

                var response = await _client.PostAsync(loginUrl, formData);
                var body = await response.Content.ReadAsStringAsync();

                // Check for successful login indicators
                var isSuccess = IsLoginSuccessful(body, (int)response.StatusCode, username, password);

                if (isSuccess && foundCredentials.Add($"{username}:{password}"))
                {
                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = "Weak Credentials",
                        Severity = "Critical",
                        Url = loginUrl,
                        Parameter = "username/password",
                        Payload = $"{username}:{password}",
                        Description = $"Login succeeded with weak credentials: '{username}:{password}'. These are easily guessable.",
                        Evidence = $"Response status: {(int)response.StatusCode}, body length: {body.Length}",
                        Remediation = "Enforce strong password policies (min 12 chars, mixed case, numbers, symbols). Implement MFA. Disable default accounts.",
                        Module = "CredentialTester",
                        Confidence = 95
                    });
                    Logger.LogVulnerability(result.Vulnerabilities.Last());
                }

                // Rate limit
                await Task.Delay(requestDelay);
            }
            catch (Exception ex)
            {
                Logger.Debug($"Credential test failed for {username}:{password}: {ex.Message}");
            }
        }
    }

    private async Task TestUsernameEnumerationAsync(ScanResult result, string loginUrl)
    {
        foreach (var (validUser, invalidUser) in UserEnumPairs.Take(2))
        {
            try
            {
                result.RequestsSent++;

                // Test valid-looking username with known-bad password
                var validReq = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("username", validUser),
                    new KeyValuePair<string, string>("password", "wrong_password_12345"),
                });
                var validResp = await _client.PostAsync(loginUrl, validReq);
                var validBody = await validResp.Content.ReadAsStringAsync();

                await Task.Delay(TimeSpan.FromSeconds(1));

                result.RequestsSent++;

                // Test obviously invalid username with same bad password
                var invalidReq = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("username", invalidUser),
                    new KeyValuePair<string, string>("password", "wrong_password_12345"),
                });
                var invalidResp = await _client.PostAsync(loginUrl, invalidReq);
                var invalidBody = await invalidResp.Content.ReadAsStringAsync();

                // Compare responses: if they differ meaningfully, user enumeration is possible
                bool differentStatus = validResp.StatusCode != invalidResp.StatusCode;
                bool differentLength = Math.Abs(validBody.Length - invalidBody.Length) > 50;
                bool differentMessage = DetectDifferentErrorMessage(validBody, invalidBody);

                if (differentStatus || differentLength || differentMessage)
                {
                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = "Username Enumeration",
                        Severity = "Medium",
                        Url = loginUrl,
                        Parameter = "username",
                        Payload = $"{validUser} vs {invalidUser}",
                        Description = $"Server responds differently for valid ({validUser}) vs invalid ({invalidUser}) usernames. Attackers can enumerate users.",
                        Evidence = $"Status: {validResp.StatusCode} vs {invalidResp.StatusCode}, Body lengths: {validBody.Length} vs {invalidBody.Length}",
                        Remediation = "Return identical error messages for invalid usernames and invalid passwords. Do not leak user existence.",
                        Module = "CredentialTester",
                        Confidence = differentStatus ? 90 : (differentLength ? 75 : 50)
                    });
                    Logger.LogVulnerability(result.Vulnerabilities.Last());
                    break; // One confirmation is enough
                }
            }
            catch (Exception ex)
            {
                Logger.Debug($"User enumeration test failed: {ex.Message}");
            }
        }
    }

    private async Task TestAccountLockoutAsync(ScanResult result, string loginUrl)
    {
        try
        {
            // Send rapid login attempts to trigger lockout
            bool rateLimited = false;
            int attemptsBeforeLockout = 0;

            for (int i = 0; i < 10; i++)
            {
                result.RequestsSent++;
                var formData = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("username", "test_lockout_user"),
                    new KeyValuePair<string, string>("password", $"wrong_password_{i}"),
                });

                var response = await _client.PostAsync(loginUrl, formData);
                var body = await response.Content.ReadAsStringAsync();

                if (response.StatusCode == HttpStatusCode.TooManyRequests ||
                    response.StatusCode == (HttpStatusCode)429 ||
                    body.Contains("too many", StringComparison.OrdinalIgnoreCase) ||
                    body.Contains("lock", StringComparison.OrdinalIgnoreCase) ||
                    body.Contains("try again", StringComparison.OrdinalIgnoreCase) ||
                    body.Contains("rate limit", StringComparison.OrdinalIgnoreCase))
                {
                    rateLimited = true;
                    attemptsBeforeLockout = i + 1;
                    break;
                }

                // No delay — we're testing lockout speed
            }

            if (rateLimited)
            {
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "Account Lockout Detected",
                    Severity = "Info",
                    Url = loginUrl,
                    Parameter = "login attempts",
                    Payload = attemptsBeforeLockout.ToString(),
                    Description = $"Account lockout/rate limiting triggered after {attemptsBeforeLockout} failed attempts. This is a good security control.",
                    Evidence = $"Lockout after {attemptsBeforeLockout} attempts",
                    Remediation = "Ensure lockout threshold is reasonable (5-10 attempts). Consider progressive delays.",
                    Module = "CredentialTester",
                    Confidence = 80
                });
                Logger.LogVulnerability(result.Vulnerabilities.Last());
            }
            else
            {
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "No Brute Force Protection",
                    Severity = "High",
                    Url = loginUrl,
                    Parameter = "login attempts",
                    Payload = "10 attempts without lockout",
                    Description = "Ten rapid failed login attempts were not rate-limited or blocked. Brute force attacks are possible.",
                    Evidence = "No lockout after 10 rapid attempts",
                    Remediation = "Implement rate limiting (e.g., 5 attempts per minute per IP/account). Add account lockout with progressive delays. Consider CAPTCHA.",
                    Module = "CredentialTester",
                    Confidence = 85
                });
                Logger.LogVulnerability(result.Vulnerabilities.Last());
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"Lockout test failed: {ex.Message}");
        }
    }

    // --- Helpers ---

    private static bool IsLoginSuccessful(string responseBody, int statusCode, string username, string password)
    {
        // Empty credentials: only flag if the server redirects or returns a 200 with session
        if (string.IsNullOrEmpty(password) && statusCode >= 400)
            return false;

        // Status-based indicators
        if (statusCode is 302 or 301 or 303 or 307 or 308)
        {
            // Redirect after login often means success (especially to /dashboard, /home, etc.)
            return true;
        }

        // Body-based indicators
        var lower = responseBody.ToLowerInvariant();
        var successIndicators = new[]
        {
            "welcome", "dashboard", "logout", "sign out", "sign-out",
            "successfully logged in", "login successful", "authenticated",
            "session", "access_token", "token", "jwt"
        };

        var failureIndicators = new[]
        {
            "invalid username", "invalid password", "incorrect password",
            "wrong password", "user not found", "invalid credentials",
            "login failed", "auth failed", "unauthorized",
            "please try again", "bad credentials"
        };

        bool hasSuccess = successIndicators.Any(i => lower.Contains(i));
        bool hasFailure = failureIndicators.Any(i => lower.Contains(i));

        if (hasSuccess && !hasFailure) return true;
        if (hasFailure) return false;

        // Fallback: 200 OK without failure messages for non-empty creds could be success
        if (statusCode == 200 && !hasFailure && !string.IsNullOrEmpty(password))
            return true;

        return false;
    }

    private static bool DetectDifferentErrorMessage(string a, string b)
    {
        // Extract error-like messages from both responses
        var errorPatterns = new[]
        {
            @"(invalid|incorrect|wrong|not found|doesn't match)[^.!?]{0,50}",
            @"(user|account|credential|login|password)[^.!?]{0,80}",
            @"(error|failed|failure)[^.!?]{0,50}",
        };

        foreach (var pattern in errorPatterns)
        {
            var matchesA = Regex.Matches(a, pattern, RegexOptions.IgnoreCase);
            var matchesB = Regex.Matches(b, pattern, RegexOptions.IgnoreCase);

            var textsA = matchesA.Select(m => m.Value.ToLowerInvariant()).ToList();
            var textsB = matchesB.Select(m => m.Value.ToLowerInvariant()).ToList();

            // If one has error messages the other doesn't, that's a signal
            if (textsA.Count != textsB.Count) return true;

            // Check content differences
            var diff = textsA.Except(textsB).Count() + textsB.Except(textsA).Count();
            if (diff > 0) return true;
        }

        // Check for username-specific words in each
        foreach (var p in new[] { "user", "account", "email" })
        {
            bool inA = a.Contains(p, StringComparison.OrdinalIgnoreCase);
            bool inB = b.Contains(p, StringComparison.OrdinalIgnoreCase);
            if (inA != inB) return true;
        }

        return false;
    }
}
