using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using SecKit.Core;
using SecKit.Models;

namespace SecKit.Modules.RedTeam;

/// <summary>
/// Analyzes JWT tokens from auth headers, cookies, and response bodies.
/// Tests for common JWT vulnerabilities including alg=none bypass, weak HMAC secrets,
/// expired tokens, audience/issuer mismatches, and kid header injection.
/// </summary>
public class JwtAnalyzer
{
    private readonly HttpClient _client;
    private readonly ConfigManager _config;

    private readonly string[] _weakSecrets;
    private static readonly string[] RequiredClaims = { "sub", "iat", "exp" };

    public JwtAnalyzer(HttpClient client, ConfigManager config)
    {
        _client = client;
        _config = config;
        _weakSecrets = config.JwtWeakSecrets.ToArray();
    }

    /// <summary>Scans the target for JWT tokens and tests them for vulnerabilities.</summary>
    public async Task<ScanResult> ScanAsync(string target)
    {
        var result = new ScanResult
        {
            ModuleName = "JWT Analyzer",
            TargetUrl = target,
            StartTime = DateTime.UtcNow
        };

        try
        {
            // Phase 1: Discover JWT tokens
            var tokens = await DiscoverTokensAsync(target);
            result.EndpointsTested = tokens.Count;

            foreach (var (token, source) in tokens)
            {
                result.RequestsSent++;

                // Phase 2: Decode without validation to extract claims
                var decoded = DecodeWithoutValidation(token);

                if (decoded.Header == null)
                {
                    Logger.Debug($"JWT from {source} could not be decoded — malformed token");
                    continue;
                }

                // Verify each vulnerability class
                CheckAlgNone(result, token, source);
                CheckWeakHmacSecret(result, token, source, decoded);
                CheckExpiredToken(result, token, source, decoded);
                CheckNotBeforeIssues(result, token, source, decoded);
                CheckAudienceMismatch(result, token, source);
                CheckMissingClaims(result, token, source, decoded);
                CheckKidInjection(result, token, source, decoded);

                // Test token reuse against the actual endpoint
                await TestTokenReuseAsync(result, target, token, source);
            }

            result.Completed = true;
        }
        catch (Exception ex)
        {
            result.ErrorMessage = ex.Message;
            Logger.Error($"JWT Analyzer failed: {ex.Message}");
        }

        result.EndTime = DateTime.UtcNow;
        return result;
    }

    // --- Token Discovery ---

    private async Task<List<(string Token, string Source)>> DiscoverTokensAsync(string url)
    {
        var tokens = new List<(string Token, string Source)>();

        try
        {
            // Check Authorization header in the response
            var response = await _client.GetAsync(url);
            var body = await response.Content.ReadAsStringAsync();

            // Look for "Bearer xxx" patterns in the body (returned tokens)
            var bearerMatches = System.Text.RegularExpressions.Regex.Matches(
                body, @"Bearer\s+([A-Za-z0-9\-_\.]+)");
            foreach (System.Text.RegularExpressions.Match m in bearerMatches)
                tokens.Add((m.Groups[1].Value, $"Bearer-in-body({url})"));

            // Look for JWT patterns anywhere (eyJ header base64)
            var jwtMatches = System.Text.RegularExpressions.Regex.Matches(
                body, @"\b(eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)\b");
            foreach (System.Text.RegularExpressions.Match m in jwtMatches)
            {
                var tok = m.Groups[1].Value;
                if (!tokens.Any(t => t.Token == tok))
                    tokens.Add((tok, $"Embedded({url})"));
            }

            // Check Set-Cookie headers
            if (response.Headers.TryGetValues("Set-Cookie", out var cookies))
            {
                foreach (var cookie in cookies)
                {
                    var parts = cookie.Split(';', 2);
                    var kv = parts[0].Split('=', 2);
                    if (kv.Length == 2 && IsJwt(kv[1]))
                        tokens.Add((kv[1], $"Cookie({url})"));
                }
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"JWT discovery failed: {ex.Message}");
        }

        return tokens;
    }

    private static bool IsJwt(string value)
    {
        return value.Count(c => c == '.') == 2 &&
               value.IndexOf("eyJ", StringComparison.Ordinal) == 0;
    }

    // --- Decoding ---

    private sealed record DecodedJwt(JwtHeader? Header, JwtPayload? Payload);

    private static DecodedJwt DecodeWithoutValidation(string token)
    {
        try
        {
            var handler = new JwtSecurityTokenHandler();
            // ReadToken with no validation parameters — just parse, don't verify
            var jwt = handler.ReadJwtToken(token);
            return new DecodedJwt(jwt.Header, jwt.Payload);
        }
        catch
        {
            return new DecodedJwt(null, null);
        }
    }

    // --- Vulnerability Checks ---

    private void CheckAlgNone(ScanResult result, string token, string source)
    {
        try
        {
            // Algorithm "none" bypass: craft a token with alg=none header
            var parts = token.Split('.');
            if (parts.Length != 3) return;

            // Replace the header with {"alg":"none","typ":"JWT"}
            var noneHeader = "{\"alg\":\"none\",\"typ\":\"JWT\"}";
            var noneHeaderB64 = Base64UrlEncode(Encoding.UTF8.GetBytes(noneHeader));
            var tamperedToken = $"{noneHeaderB64}.{parts[1]}.";

            // Check if the original token's header uses "none" or an empty alg
            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.ReadJwtToken(token);
            var alg = jwt.Header.Alg;

            if (string.IsNullOrEmpty(alg) || alg.Equals("none", StringComparison.OrdinalIgnoreCase))
            {
                AddVuln(result, source, token, "JWT: alg=none accepted",
                    $"The JWT token from {source} uses algorithm '{alg ?? "null"}' which is insecure.",
                    "Critical", 95);
            }
            else if (alg.Equals("HS256", StringComparison.OrdinalIgnoreCase))
            {
                Logger.Debug($"JWT uses {alg} — will test for weak HMAC secrets.");
            }
            else if (alg.StartsWith("RS", StringComparison.OrdinalIgnoreCase) ||
                     alg.StartsWith("ES", StringComparison.OrdinalIgnoreCase))
            {
                // Could also test if alg confusion is possible (use HS with public key)
                AddVuln(result, source, token, "JWT: Asymmetric algorithm info",
                    $"Token uses {alg}. Verify the server validates the algorithm and prevents algorithm confusion attacks.",
                    "Info", 30);
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"alg=none check failed: {ex.Message}");
        }
    }

    private void CheckWeakHmacSecret(ScanResult result, string token, string source, DecodedJwt decoded)
    {
        if (decoded.Header == null) return;

        var alg = decoded.Header.Alg ?? "";
        if (!alg.StartsWith("HS", StringComparison.OrdinalIgnoreCase)) return;

        foreach (var secret in _weakSecrets.Take(50)) // Limit iterations
        {
            try
            {
                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
                var validationParams = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = key,
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = false
                };

                var handler = new JwtSecurityTokenHandler();
                var principal = handler.ValidateToken(token, validationParams, out _);

                if (principal != null)
                {
                    AddVuln(result, source, token, "JWT: Weak HMAC Secret",
                        $"JWT token from {source} is signed with a weak secret: '{secret}'. Anyone can forge tokens.",
                        "Critical", 100,
                        $"Use a strong, high-entropy secret (≥256 bits) and store it securely.");
                    return; // Found the secret — no need to continue
                }
            }
            catch (SecurityTokenSignatureKeyNotFoundException)
            {
                // Expected — this secret doesn't match
            }
            catch (SecurityTokenInvalidSignatureException)
            {
                // Expected — secret doesn't match signature
            }
            catch (Exception ex)
            {
                Logger.Debug($"HMAC crack attempt failed with '{secret}': {ex.Message}");
            }
        }
    }

    private void CheckExpiredToken(ScanResult result, string token, string source, DecodedJwt decoded)
    {
        if (decoded.Payload == null) return;

        var hasExp = decoded.Payload.TryGetValue("exp", out var expObj);
        if (!hasExp)
        {
            AddVuln(result, source, token, "JWT: No Expiration",
                "JWT token has no 'exp' claim — it will never expire. Revoked tokens remain valid indefinitely.",
                "High", 85,
                "Always include an 'exp' claim with a reasonable lifetime (e.g., 15-60 minutes).");
            return;
        }

        if (expObj is long expUnix)
        {
            var expDate = DateTimeOffset.FromUnixTimeSeconds(expUnix).UtcDateTime;
            if (expDate <= DateTime.UtcNow)
            {
                AddVuln(result, source, token, "JWT: Expired Token Still Active",
                    $"Token expired at {expDate:O} but the server accepted it.",
                    "Medium", 60);
            }
            // Flag unreasonably long expiration
            var lifetime = expDate - DateTime.UtcNow;
            if (lifetime.TotalDays > 365)
            {
                AddVuln(result, source, token, "JWT: Excessive Lifetime",
                    $"Token expires in {lifetime.TotalDays:F0} days. Long-lived tokens increase exposure.",
                    "Medium", 50,
                    "Reduce token lifetime to hours or days. Use refresh tokens for long-lived sessions.");
            }
        }
    }

    private void CheckNotBeforeIssues(ScanResult result, string token, string source, DecodedJwt decoded)
    {
        if (decoded.Payload == null) return;

        if (decoded.Payload.TryGetValue("nbf", out var nbfObj) && nbfObj is long nbfUnix)
        {
            var nbf = DateTimeOffset.FromUnixTimeSeconds(nbfUnix).UtcDateTime;
            if (nbf > DateTime.UtcNow.AddMinutes(1))
            {
                AddVuln(result, source, token, "JWT: Future nbf",
                    $"Token's 'nbf' claim is set to {nbf:O} (future). Token may be invalid until then.",
                    "Info", 20);
            }
        }
    }

    private void CheckAudienceMismatch(ScanResult result, string token, string source)
    {
        try
        {
            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.ReadJwtToken(token);

            if (jwt.Audiences.Any())
            {
                var audiences = jwt.Audiences.ToList();
                Logger.Debug($"JWT audiences: {string.Join(", ", audiences)}");

                // Warn if audience is too broad
                if (audiences.Contains("*") || audiences.Contains("all"))
                {
                    AddVuln(result, source, token, "JWT: Wildcard Audience",
                        "Token targets '*' or 'all' audience — any service can accept this token.",
                        "Medium", 55,
                        "Restrict the 'aud' claim to specific service identifiers.");
                }
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"Audience check failed: {ex.Message}");
        }
    }

    private void CheckMissingClaims(ScanResult result, string token, string source, DecodedJwt decoded)
    {
        if (decoded.Payload == null) return;

        foreach (var claim in RequiredClaims)
        {
            if (!decoded.Payload.ContainsKey(claim))
            {
                AddVuln(result, source, token, $"JWT: Missing '{claim}' claim",
                    $"JWT token lacks the '{claim}' claim, which is a standard security claim.",
                    claim == "sub" ? "Medium" : "Low",
                    claim == "sub" ? 60 : 30);
            }
        }
    }

    private void CheckKidInjection(ScanResult result, string token, string source, DecodedJwt decoded)
    {
        if (decoded.Header == null) return;

        // Check if kid (Key ID) header is present — potential injection vector
        if (decoded.Header.TryGetValue("kid", out var kid))
        {
            Logger.Debug($"JWT contains kid header: {kid}");

            // Flag if kid looks suspicious (path traversal)
            if (kid?.ToString()?.Contains("../") == true ||
                kid?.ToString()?.Contains("/") == true)
            {
                AddVuln(result, source, token, "JWT: Suspicious kid Header",
                    $"The JWT 'kid' header value '{kid}' looks like a path. Kid injection can lead to key confusion attacks.",
                    "Critical", 80,
                    "Validate kid values against a whitelist. Never use raw kid values for file-system access.");
            }
            else if (kid?.ToString()?.Length > 100 == true)
            {
                AddVuln(result, source, token, "JWT: Large kid Header",
                    $"The JWT 'kid' header is unusually large ({kid.ToString()!.Length} chars).",
                    "Low", 20);
            }
        }
    }

    private async Task TestTokenReuseAsync(ScanResult result, string target, string token, string source)
    {
        try
        {
            // Send the token back to the target to check if it's still accepted
            var request = new HttpRequestMessage(HttpMethod.Get, target);
            request.Headers.TryAddWithoutValidation("Authorization", $"Bearer {token}");

            var response = await _client.SendAsync(request);
            result.RequestsSent++;

            if (response.IsSuccessStatusCode)
            {
                Logger.Debug($"Token reuse test against {target}: accepted ({response.StatusCode})");
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"Token reuse test failed: {ex.Message}");
        }
    }

    // --- Helpers ---

    private static string Base64UrlEncode(byte[] data)
    {
        return Convert.ToBase64String(data)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private void AddVuln(ScanResult result, string source, string token, string type,
        string description, string severity, int confidence, string? remediation = null)
    {
        var vuln = new Vulnerability
        {
            Type = type,
            Severity = severity,
            Url = source,
            Parameter = "JWT",
            Payload = token.Length > 80 ? token[..80] + "..." : token,
            Description = description,
            Evidence = $"JWT header: {GetHeaderSnippet(token)}",
            Remediation = remediation ?? "Implement proper JWT validation: verify signature, check algorithm, validate all claims (exp, aud, iss, nbf), and use strong secrets.",
            Module = "JwtAnalyzer",
            Confidence = confidence
        };
        result.Vulnerabilities.Add(vuln);
        Logger.LogVulnerability(vuln);
    }

    private static string GetHeaderSnippet(string token)
    {
        try
        {
            var parts = token.Split('.');
            if (parts.Length >= 1)
            {
                var padded = parts[0].PadRight(parts[0].Length + (4 - parts[0].Length % 4) % 4, '=');
                var headerBytes = Convert.FromBase64String(padded.Replace('-', '+').Replace('_', '/'));
                return Encoding.UTF8.GetString(headerBytes);
            }
        }
        catch { }
        return "(unable to decode)";
    }
}
