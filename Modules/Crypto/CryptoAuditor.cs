#pragma warning disable CS1998
using System.IdentityModel.Tokens.Jwt;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.IdentityModel.Tokens;
using SecKit.Core;
using SecKit.Models;

namespace SecKit.Modules.Crypto;

/// <summary>
/// Comprehensive cryptographic auditor. Tests JWT algorithm confusion, hash identification,
/// TLS certificate chain analysis, RNG entropy validation, and cryptographic misuse detection.
/// </summary>
public class CryptoAuditor
{
    private readonly HttpClient _client;
    private readonly ConfigManager _config;
    private readonly HashSet<string> _commonPasswords;
    private readonly (Regex Pattern, string Name)[] _hashPatterns;
    private readonly (Regex Pattern, string Algorithm, string Severity, string Desc)[] _misusePatterns;

    public CryptoAuditor(HttpClient client, ConfigManager config)
    {
        _client = client;
        _config = config;
        _commonPasswords = config.CommonPasswords;

        _hashPatterns = config.HashPatterns
            .Select(h => (new Regex(h.Pattern, RegexOptions.IgnoreCase), h.Name)).ToArray();

        _misusePatterns = config.CryptoMisusePatterns
            .Select(m => (new Regex(m.Pattern, RegexOptions.IgnoreCase), m.Algorithm, m.Severity, m.Description)).ToArray();
    }

    public async Task<ScanResult> ScanAsync(string target)
    {
        var result = new ScanResult { ModuleName = "Crypto Auditor", TargetUrl = target, StartTime = DateTime.UtcNow };
        try
        {
            if (Uri.TryCreate(target, UriKind.Absolute, out var uri) && (uri.Scheme == "http" || uri.Scheme == "https"))
            {
                await TestJwtAlgorithmConfusionAsync(result, uri.ToString());
                if (uri.Scheme == "https") await AnalyzeCertificateAsync(result, uri);
                await TestSourceCodeInResponseAsync(result, uri.ToString());
                await TestRngEntropyAsync(result);
            }
            else if (Directory.Exists(target))
            { await ScanDirectoryForCryptoMisuseAsync(result, target); await TestRngEntropyAsync(result); }
            else if (File.Exists(target))
            { var content = await File.ReadAllTextAsync(target); await IdentifyHashesAsync(result, target, content); await ScanSourceCodeAsync(result, target, content); await TestRngEntropyAsync(result); }
            else { await AnalyzeHashStringAsync(result, target); }
            result.Completed = true;
        }
        catch (Exception ex) { result.ErrorMessage = ex.Message; Logger.Error($"Crypto Auditor failed: {ex.Message}"); }
        result.EndTime = DateTime.UtcNow;
        return result;
    }

    private async Task TestJwtAlgorithmConfusionAsync(ScanResult result, string url)
    {
        try
        {
            var response = await _client.GetAsync(url); result.RequestsSent++;
            var body = await response.Content.ReadAsStringAsync();
            var jwtMatches = Regex.Matches(body, @"\b(eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)\b");
            foreach (Match m in jwtMatches)
            {
                var token = m.Groups[1].Value;
                try
                {
                    var handler = new JwtSecurityTokenHandler(); var jwt = handler.ReadJwtToken(token); var alg = jwt.Header.Alg ?? "unknown";
                    await TestNoneAlgBypassAsync(result, url, token);
                    if (alg.StartsWith("RS", StringComparison.OrdinalIgnoreCase) || alg.StartsWith("ES", StringComparison.OrdinalIgnoreCase))
                    { AddVuln(result, url, token, "JWT: Potential RS→HS Algorithm Confusion", $"Token uses {alg}. If server doesn't pin algorithm, attacker can convert to HMAC with public key.", "Critical", 90, "Pin expected algorithm per key. Reject tokens where alg doesn't match key type."); await TestJwkHeaderInjectionAsync(result, url, token); }
                    TestKidPathTraversal(result, url, token, jwt.Header);
                }
                catch { }
            }
            result.EndpointsTested++;
        }
        catch (Exception ex) { Logger.Debug($"JWT confusion test failed: {ex.Message}"); }
    }

    private async Task TestNoneAlgBypassAsync(ScanResult result, string url, string token)
    {
        try
        {
            var parts = token.Split('.'); if (parts.Length != 3) return;
            var noneHeader = Base64UrlEncode(Encoding.UTF8.GetBytes("{\"alg\":\"none\",\"typ\":\"JWT\"}"));
            var tamperedToken = $"{noneHeader}.{parts[1]}.";
            var request = new HttpRequestMessage(HttpMethod.Get, url); request.Headers.TryAddWithoutValidation("Authorization", $"Bearer {tamperedToken}");
            var response = await _client.SendAsync(request); result.RequestsSent++;
            if (response.IsSuccessStatusCode) AddVuln(result, url, token, "JWT: alg=none Accepted", "Server accepted JWT with 'alg=none'.", "Critical", 100, "Configure JWT validation to reject 'none' algorithm explicitly.");
        }
        catch (Exception ex) { Logger.Debug($"None bypass test: {ex.Message}"); }
    }

    private async Task TestJwkHeaderInjectionAsync(ScanResult result, string url, string originalToken)
    {
        try
        {
            using var rsa = RSA.Create(2048); var parameters = rsa.ExportParameters(false);
            var jwk = new Dictionary<string, object> { ["kty"] = "RSA", ["n"] = Base64UrlEncode(parameters.Modulus!), ["e"] = Base64UrlEncode(parameters.Exponent!), ["alg"] = "RS256" };
            var parts = originalToken.Split('.'); if (parts.Length != 3) return;
            var injectedHeader = JsonSerializer.Serialize(new { alg = "RS256", typ = "JWT", jwk });
            var injectedHeaderB64 = Base64UrlEncode(Encoding.UTF8.GetBytes(injectedHeader));
            var signingInput = Encoding.UTF8.GetBytes($"{injectedHeaderB64}.{parts[1]}");
            var signature = rsa.SignData(signingInput, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var tamperedToken = $"{injectedHeaderB64}.{parts[1]}.{Base64UrlEncode(signature)}";
            var request = new HttpRequestMessage(HttpMethod.Get, url); request.Headers.TryAddWithoutValidation("Authorization", $"Bearer {tamperedToken}"); result.RequestsSent++;
            if ((await _client.SendAsync(request)).IsSuccessStatusCode) AddVuln(result, url, originalToken, "JWT: JWK Header Injection Accepted", "Server accepted JWT with attacker-injected 'jwk' header.", "Critical", 100, "Never trust 'jwk' header.");
        }
        catch (Exception ex) { Logger.Debug($"JWK injection test: {ex.Message}"); }
    }

    private void TestKidPathTraversal(ScanResult result, string url, string token, JwtHeader header)
    {
        if (!header.TryGetValue("kid", out var kid)) return; var kidStr = kid?.ToString() ?? "";
        if (kidStr.Contains("../") || kidStr.Contains("..\\")) AddVuln(result, url, token, "JWT: kid Path Traversal", $"kid header '{kidStr}' contains path traversal.", "Critical", 85, "Validate kid against strict whitelist.");
        else if (kidStr.Contains("/etc/") || kidStr.Contains("\\Windows\\")) AddVuln(result, url, token, "JWT: Absolute Path in kid", $"kid header contains absolute path: '{kidStr}'.", "High", 70, "Use opaque identifiers for kid.");
        else if (kidStr.Contains("/")) AddVuln(result, url, token, "JWT: Path-Like kid Header", $"kid '{kidStr}' contains path separators.", "Medium", 50, "Use non-path opaque identifiers for kid.");
        if (kidStr.Contains('\0') || kidStr.Contains("%00")) AddVuln(result, url, token, "JWT: NULL Byte in kid", "kid header contains NULL byte.", "Critical", 95, "Reject tokens with NULL bytes in header values.");
    }

    private async Task IdentifyHashesAsync(ScanResult result, string source, string content)
    {
        var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries); var found = 0;
        foreach (var line in lines.Take(1000))
        {
            if (line.Length < 16 || line.Length > 200) continue;
            foreach (var (pattern, algoName) in _hashPatterns)
            {
                if (pattern.IsMatch(line))
                {
                    found++;
                    var hashValue = line.Contains(':') ? line.Split(':', 2)[^1] : line;
                    var cracked = await TryCrackHashAsync(hashValue, algoName);
                    if (cracked != null) AddVuln(result, source, hashValue, $"Hash Cracked: {algoName}", $"Hash ({algoName}) matched common password: '{cracked}'.", "Critical", 95, "Use a strong, unique password.");
                    else if (algoName.StartsWith("MD5") || algoName.StartsWith("SHA-1")) AddVuln(result, source, hashValue, $"Weak Hash: {algoName}", $"{algoName} hash found — algorithm is cryptographically weak.", "High", 80, "Use bcrypt, argon2, or scrypt.");
                    break;
                }
            }
        }
        if (found > 0) result.EndpointsTested++;
    }

    private async Task<string?> TryCrackHashAsync(string hashValue, string algoName)
    {
        await Task.CompletedTask;
        foreach (var password in _commonPasswords)
        {
            string? computed = algoName switch { "MD5" => ComputeMd5(password), "SHA-1" => ComputeSha1(password), "SHA-256" => ComputeSha256(password), "NTLM" => ComputeNtlm(password), _ => null };
            if (computed != null && string.Equals(computed, hashValue, StringComparison.OrdinalIgnoreCase)) return password;
        }
        return null;
    }

    private async Task AnalyzeHashStringAsync(ScanResult result, string hashValue)
    {
        foreach (var (pattern, algoName) in _hashPatterns)
        {
            if (pattern.IsMatch(hashValue))
            {
                result.EndpointsTested++; var cracked = await TryCrackHashAsync(hashValue, algoName);
                if (cracked != null) AddVuln(result, "direct", hashValue, $"Hash Cracked: {algoName}", $"Cracked: '{cracked}'.", "Critical", 95, "Use a strong, unique password.");
                else { var sev = algoName is "MD5" or "SHA-1" ? "High" : "Medium"; AddVuln(result, "direct", hashValue, $"Hash Identified: {algoName}", $"Hash type: {algoName}.{(sev == "High" ? " Algorithm is weak." : "")}", sev, sev == "High" ? 80 : 40, sev == "High" ? "Upgrade to bcrypt, argon2, or scrypt." : null); }
                return;
            }
        }
    }

    private async Task AnalyzeCertificateAsync(ScanResult result, Uri uri)
    {
        await Task.CompletedTask;
        try
        {
            using var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (_, cert, chain, errors) =>
                {
                    if (cert == null) return true;
                    if (chain == null || chain.ChainElements.Count <= 1) AddVuln(result, uri.ToString(), "", "TLS: Self-Signed Certificate", "Server uses self-signed cert.", "Medium", 70, "Use a certificate from a trusted CA.");
                    var sigAlg = cert.SignatureAlgorithm.FriendlyName ?? cert.SignatureAlgorithm.Value ?? "";
                    if (sigAlg.Contains("sha1", StringComparison.OrdinalIgnoreCase) || sigAlg.Contains("md5", StringComparison.OrdinalIgnoreCase)) AddVuln(result, uri.ToString(), "", "TLS: Weak Signature Algorithm", $"Certificate signed with {sigAlg}.", "High", 85, "Replace with SHA-256 or stronger.");
                    using var rsaKey = cert.GetRSAPublicKey();
                    if (rsaKey != null && rsaKey.KeySize < 2048) AddVuln(result, uri.ToString(), "", "TLS: Short RSA Key", $"RSA key is only {rsaKey.KeySize} bits.", "High", 85, "Re-issue with ≥2048-bit RSA key.");
                    var daysToExpiry = (cert.NotAfter - DateTime.Now).TotalDays;
                    if (daysToExpiry < 30 && daysToExpiry > 0) AddVuln(result, uri.ToString(), "", "TLS: Certificate Expiring Soon", $"Expires in {daysToExpiry:F0} days.", "Medium", 60, "Renew before expiration.");
                    return true;
                }
            };
            using var testClient = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
            await testClient.GetAsync(uri); result.RequestsSent++; result.EndpointsTested++;
        }
        catch (Exception ex) { Logger.Debug($"Certificate analysis failed: {ex.Message}"); }
    }

    private async Task TestRngEntropyAsync(ScanResult result)
    {
        try
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) && File.Exists("/proc/sys/kernel/random/entropy_avail"))
            {
                var entropy = await File.ReadAllTextAsync("/proc/sys/kernel/random/entropy_avail");
                if (int.TryParse(entropy.Trim(), out var bits) && bits < 100) AddVuln(result, "system", "", "RNG: Low Entropy Pool", $"System entropy: {bits} bits.", "Medium", 50, "Install haveged or rng-tools.");
            }
        }
        catch (Exception ex) { Logger.Debug($"RNG check: {ex.Message}"); }
    }

    private async Task TestSourceCodeInResponseAsync(ScanResult result, string url)
    {
        try { var response = await _client.SendAsync(new HttpRequestMessage(HttpMethod.Get, url)); result.RequestsSent++; var body = await response.Content.ReadAsStringAsync(); await ScanSourceCodeAsync(result, url, body); } catch (Exception ex) { Logger.Debug($"Source code scan failed: {ex.Message}"); }
    }

    private async Task ScanSourceCodeAsync(ScanResult result, string source, string code)
    {
        foreach (var (pattern, algo, severity, desc) in _misusePatterns)
        {
            var matches = pattern.Matches(code);
            foreach (Match match in matches)
            {
                AddVuln(result, source, "", $"Crypto Misuse: {algo}", desc, severity, severity == "Critical" ? 95 : severity == "High" ? 80 : 50,
                    algo switch { "MD5" => "Replace with SHA-256 or SHA-3.", "SHA-1" => "Replace with SHA-256 or SHA-3.", "DES" => "Replace with AES-256.", "RC4" => "Use AES-GCM or ChaCha20.", "ECB mode" => "Use CBC with random IVs or GCM.", "3DES" => "Replace with AES.", "System.Random" => "Use RandomNumberGenerator.", "Math.random()" => "Use a CSPRNG.", _ => "Replace with modern cryptographic algorithms." });
            }
        }
    }

    private async Task ScanDirectoryForCryptoMisuseAsync(ScanResult result, string directory)
    {
        var exts = new[] { ".cs", ".java", ".js", ".ts", ".php", ".py", ".rb", ".go", ".rs", ".c", ".cpp", ".h" }; result.EndpointsTested++;
        foreach (var ext in exts) foreach (var file in Directory.GetFiles(directory, $"*{ext}", SearchOption.AllDirectories).Take(200)) { try { await ScanSourceCodeAsync(result, file, await File.ReadAllTextAsync(file)); } catch { } }
    }

    private static string Base64UrlEncode(byte[] data) => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static string ComputeMd5(string input) => Convert.ToHexString(MD5.HashData(Encoding.UTF8.GetBytes(input))).ToLowerInvariant();
    private static string ComputeSha1(string input) => Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(input))).ToLowerInvariant();
    private static string ComputeSha256(string input) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(input))).ToLowerInvariant();
    private static string ComputeNtlm(string input) => "";

    private void AddVuln(ScanResult result, string source, string token, string type, string description, string severity, int confidence, string? remediation = null)
    {
        result.Vulnerabilities.Add(new Vulnerability { Type = type, Severity = severity, Url = source, Parameter = "Crypto", Payload = token.Length > 80 ? token[..80] + "..." : token, Description = description, Remediation = remediation ?? "Follow cryptographic best practices.", Module = "CryptoAuditor", Confidence = confidence });
        Logger.LogVulnerability(result.Vulnerabilities[^1]);
    }
}
