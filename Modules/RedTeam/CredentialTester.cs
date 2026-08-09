using System.Collections.Concurrent;
using System.Net;
using System.Text.RegularExpressions;
using SecKit.Core;
using SecKit.Models;

namespace SecKit.Modules.RedTeam;

/// <summary>Tests login endpoints for weak credentials, account lockout behavior, and username enumeration vulnerabilities. Rate-limited from config.</summary>
public class CredentialTester
{
    private readonly HttpClient _client;
    private readonly ConfigManager _config;
    private readonly (string User, string Pass)[] _weakCredentials;
    private readonly string[] _loginPaths;
    private readonly (string ValidUser, string InvalidUser)[] _userEnumPairs;
    private readonly int _requestDelayMs;

    public CredentialTester(HttpClient client, ConfigManager config)
    {
        _client = client;
        _config = config;
        _weakCredentials = config.WeakCredentials.Select(c => (c.User, c.Pass)).ToArray();
        _loginPaths = config.LoginPaths.ToArray();
        _userEnumPairs = config.UserEnumerationPairs.Select(p => (p.ValidUser, p.InvalidUser)).ToArray();
        _requestDelayMs = Math.Max(100, 1000 / Math.Max(1, config.CredentialRequestsPerSecond));
    }

    public async Task<ScanResult> ScanAsync(string target)
    {
        var result = new ScanResult { ModuleName = "Credential Tester", TargetUrl = target, StartTime = DateTime.UtcNow };
        try
        {
            var loginUrl = await DiscoverLoginEndpointAsync(target);
            if (loginUrl == null) { Logger.Warning("No login endpoint discovered on target."); result.Completed = true; result.EndTime = DateTime.UtcNow; return result; }

            result.EndpointsTested = 1;
            Logger.Info($"Testing credentials against {loginUrl}...");
            await TestWeakCredentialsAsync(result, loginUrl);
            await TestUsernameEnumerationAsync(result, loginUrl);
            await TestAccountLockoutAsync(result, loginUrl);
            result.Completed = true;
        }
        catch (Exception ex) { result.ErrorMessage = ex.Message; Logger.Error($"Credential Tester failed: {ex.Message}"); }
        result.EndTime = DateTime.UtcNow;
        return result;
    }

    private async Task<string?> DiscoverLoginEndpointAsync(string target)
    {
        foreach (var path in _loginPaths)
        {
            try
            {
                var url = new Uri(new Uri(target), path).ToString();
                var response = await _client.GetAsync(url);
                var body = await response.Content.ReadAsStringAsync();
                var hasForm = body.Contains("<form", StringComparison.OrdinalIgnoreCase) && (body.Contains("password", StringComparison.OrdinalIgnoreCase) || body.Contains("passwd", StringComparison.OrdinalIgnoreCase));
                if (hasForm && response.IsSuccessStatusCode) { Logger.Info($"Found login endpoint: {url}"); return url; }
                if (response.StatusCode == HttpStatusCode.MethodNotAllowed) { Logger.Debug($"Found potential API login at {url} (405 on GET)"); return url; }
            }
            catch (Exception ex) { Logger.Debug($"Login discovery failed for {path}: {ex.Message}"); }
        }

        try
        {
            var response = await _client.GetAsync(target);
            var body = await response.Content.ReadAsStringAsync();
            if (body.Contains("<form", StringComparison.OrdinalIgnoreCase) && body.Contains("password", StringComparison.OrdinalIgnoreCase)) return target;
        }
        catch { }
        return null;
    }

    private async Task TestWeakCredentialsAsync(ScanResult result, string loginUrl)
    {
        var foundCredentials = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var requestDelay = TimeSpan.FromMilliseconds(_requestDelayMs);

        foreach (var (username, password) in _weakCredentials)
        {
            try
            {
                result.RequestsSent++;
                var formData = new FormUrlEncodedContent(new[] { new KeyValuePair<string, string>("username", username), new KeyValuePair<string, string>("password", password), new KeyValuePair<string, string>("email", username) });
                var response = await _client.PostAsync(loginUrl, formData);
                var body = await response.Content.ReadAsStringAsync();

                var isSuccess = IsLoginSuccessful(body, (int)response.StatusCode, username, password);
                if (isSuccess && foundCredentials.Add($"{username}:{password}"))
                {
                    result.Vulnerabilities.Add(new Vulnerability { Type = "Weak Credentials", Severity = "Critical", Url = loginUrl, Parameter = "username/password", Payload = $"{username}:{password}", Description = $"Login succeeded with weak credentials: '{username}:{password}'. These are easily guessable.", Evidence = $"Response status: {(int)response.StatusCode}, body length: {body.Length}", Remediation = "Enforce strong password policies (min 12 chars, mixed case, numbers, symbols). Implement MFA. Disable default accounts.", Module = "CredentialTester", Confidence = 95 });
                    Logger.LogVulnerability(result.Vulnerabilities.Last());
                }
                await Task.Delay(requestDelay);
            }
            catch (Exception ex) { Logger.Debug($"Credential test failed for {username}:{password}: {ex.Message}"); }
        }
    }

    private async Task TestUsernameEnumerationAsync(ScanResult result, string loginUrl)
    {
        foreach (var (validUser, invalidUser) in _userEnumPairs.Take(2))
        {
            try
            {
                result.RequestsSent++;
                var validReq = new FormUrlEncodedContent(new[] { new KeyValuePair<string, string>("username", validUser), new KeyValuePair<string, string>("password", "wrong_password_12345") });
                var validResp = await _client.PostAsync(loginUrl, validReq); var validBody = await validResp.Content.ReadAsStringAsync();
                await Task.Delay(TimeSpan.FromMilliseconds(_requestDelayMs));
                result.RequestsSent++;
                var invalidReq = new FormUrlEncodedContent(new[] { new KeyValuePair<string, string>("username", invalidUser), new KeyValuePair<string, string>("password", "wrong_password_12345") });
                var invalidResp = await _client.PostAsync(loginUrl, invalidReq); var invalidBody = await invalidResp.Content.ReadAsStringAsync();

                bool differentStatus = validResp.StatusCode != invalidResp.StatusCode;
                bool differentLength = Math.Abs(validBody.Length - invalidBody.Length) > 50;
                bool differentMessage = DetectDifferentErrorMessage(validBody, invalidBody);

                if (differentStatus || differentLength || differentMessage)
                {
                    result.Vulnerabilities.Add(new Vulnerability { Type = "Username Enumeration", Severity = "Medium", Url = loginUrl, Parameter = "username", Payload = $"{validUser} vs {invalidUser}", Description = $"Server responds differently for valid ({validUser}) vs invalid ({invalidUser}) usernames. Attackers can enumerate users.", Evidence = $"Status: {validResp.StatusCode} vs {invalidResp.StatusCode}, Body lengths: {validBody.Length} vs {invalidBody.Length}", Remediation = "Return identical error messages for invalid usernames and invalid passwords. Do not leak user existence.", Module = "CredentialTester", Confidence = differentStatus ? 90 : (differentLength ? 75 : 50) });
                    Logger.LogVulnerability(result.Vulnerabilities.Last()); break;
                }
            }
            catch (Exception ex) { Logger.Debug($"User enumeration test failed: {ex.Message}"); }
        }
    }

    private async Task TestAccountLockoutAsync(ScanResult result, string loginUrl)
    {
        try
        {
            bool rateLimited = false; int attemptsBeforeLockout = 0;
            for (int i = 0; i < 10; i++)
            {
                result.RequestsSent++;
                var formData = new FormUrlEncodedContent(new[] { new KeyValuePair<string, string>("username", "test_lockout_user"), new KeyValuePair<string, string>("password", $"wrong_password_{i}") });
                var response = await _client.PostAsync(loginUrl, formData); var body = await response.Content.ReadAsStringAsync();
                if (response.StatusCode == HttpStatusCode.TooManyRequests || response.StatusCode == (HttpStatusCode)429 || body.Contains("too many", StringComparison.OrdinalIgnoreCase) || body.Contains("lock", StringComparison.OrdinalIgnoreCase) || body.Contains("try again", StringComparison.OrdinalIgnoreCase) || body.Contains("rate limit", StringComparison.OrdinalIgnoreCase))
                { rateLimited = true; attemptsBeforeLockout = i + 1; break; }
            }

            if (rateLimited)
            {
                result.Vulnerabilities.Add(new Vulnerability { Type = "Account Lockout Detected", Severity = "Info", Url = loginUrl, Parameter = "login attempts", Payload = attemptsBeforeLockout.ToString(), Description = $"Account lockout/rate limiting triggered after {attemptsBeforeLockout} failed attempts. This is a good security control.", Evidence = $"Lockout after {attemptsBeforeLockout} attempts", Remediation = "Ensure lockout threshold is reasonable (5-10 attempts). Consider progressive delays.", Module = "CredentialTester", Confidence = 80 });
            }
            else
            {
                result.Vulnerabilities.Add(new Vulnerability { Type = "No Brute Force Protection", Severity = "High", Url = loginUrl, Parameter = "login attempts", Payload = "10 attempts without lockout", Description = "Ten rapid failed login attempts were not rate-limited or blocked. Brute force attacks are possible.", Evidence = "No lockout after 10 rapid attempts", Remediation = "Implement rate limiting (e.g., 5 attempts per minute per IP/account). Add account lockout with progressive delays. Consider CAPTCHA.", Module = "CredentialTester", Confidence = 85 });
            }
        }
        catch (Exception ex) { Logger.Debug($"Lockout test failed: {ex.Message}"); }
    }

    private static bool IsLoginSuccessful(string responseBody, int statusCode, string username, string password)
    {
        if (string.IsNullOrEmpty(password) && statusCode >= 400) return false;
        if (statusCode is 302 or 301 or 303 or 307 or 308) return true;
        var lower = responseBody.ToLowerInvariant();
        var successIndicators = new[] { "welcome", "dashboard", "logout", "sign out", "sign-out", "successfully logged in", "login successful", "authenticated", "session", "access_token", "token", "jwt" };
        var failureIndicators = new[] { "invalid username", "invalid password", "incorrect password", "wrong password", "user not found", "invalid credentials", "login failed", "auth failed", "unauthorized", "please try again", "bad credentials" };
        bool hasSuccess = successIndicators.Any(lower.Contains), hasFailure = failureIndicators.Any(lower.Contains);
        if (hasSuccess && !hasFailure) return true;
        if (hasFailure) return false;
        if (statusCode == 200 && !hasFailure && !string.IsNullOrEmpty(password)) return true;
        return false;
    }

    private static bool DetectDifferentErrorMessage(string a, string b)
    {
        var errorPatterns = new[] { @"(invalid|incorrect|wrong|not found|doesn't match)[^.!?]{0,50}", @"(user|account|credential|login|password)[^.!?]{0,80}", @"(error|failed|failure)[^.!?]{0,50}" };
        foreach (var pattern in errorPatterns)
        {
            var matchesA = Regex.Matches(a, pattern, RegexOptions.IgnoreCase).Select(m => m.Value.ToLowerInvariant()).ToList();
            var matchesB = Regex.Matches(b, pattern, RegexOptions.IgnoreCase).Select(m => m.Value.ToLowerInvariant()).ToList();
            if (matchesA.Count != matchesB.Count) return true;
            if (matchesA.Except(matchesB).Count() + matchesB.Except(matchesA).Count() > 0) return true;
        }
        foreach (var p in new[] { "user", "account", "email" }) { if (a.Contains(p, StringComparison.OrdinalIgnoreCase) != b.Contains(p, StringComparison.OrdinalIgnoreCase)) return true; }
        return false;
    }
}
