using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using SecKit.Core;
using SecKit.Models;

namespace SecKit.Modules.Secrets;

/// <summary>
/// Audits password strength, checks against common password lists,
/// queries HaveIBeenPwned via k-anonymity, and estimates brute-force crack time.
/// </summary>
public class PasswordAuditor
{
    private readonly HttpClient _client;
    private readonly ConfigManager _config;
    private readonly HashSet<string> _commonPasswords;
    private readonly List<string> _commonPatterns;

    private const int MinPasswordLength = 1;
    private const int MaxPasswordLength = 128;

    private const string HibpApiBase = "https://api.pwnedpasswords.com/range/";
    private static readonly HttpClient _hibpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(10),
        DefaultRequestHeaders = { { "User-Agent", "SecKit-PasswordAuditor/3.0" } }
    };

    public PasswordAuditor(HttpClient client, ConfigManager config)
    {
        _client = client;
        _config = config;
        _commonPasswords = config.CommonPasswords;
        _commonPatterns = config.CommonPasswordPatterns;
    }

    public async Task<ScanResult> ScanAsync(string target)
    {
        var result = new ScanResult
        {
            ModuleName = "Password Auditor",
            TargetUrl = target,
            StartTime = DateTime.UtcNow
        };

        try
        {
            if (File.Exists(target))
            {
                Logger.Info($"Auditing passwords from file: {target}");
                await AuditFileAsync(target, result);
            }
            else if (Directory.Exists(target))
            {
                Logger.Info($"Auditing password files in directory: {target}");
                var files = Directory.GetFiles(target, "*.txt", SearchOption.AllDirectories)
                    .Concat(Directory.GetFiles(target, "*.hash", SearchOption.AllDirectories))
                    .Concat(Directory.GetFiles(target, "*.passwords", SearchOption.AllDirectories))
                    .ToList();

                result.EndpointsTested = files.Count;
                foreach (var file in files)
                    await AuditFileAsync(file, result);
            }
            else
            {
                Logger.Info("Auditing single password...");
                await AuditSinglePasswordAsync(target, result);
                result.EndpointsTested = 1;
            }

            result.Completed = true;
        }
        catch (Exception ex)
        {
            result.ErrorMessage = ex.Message;
            Logger.Error($"Password auditor failed: {ex.Message}");
        }

        result.EndTime = DateTime.UtcNow;
        return result;
    }

    private async Task AuditFileAsync(string filePath, ScanResult result)
    {
        try
        {
            var lines = await File.ReadAllLinesAsync(filePath);
            foreach (var line in lines)
            {
                var trimmed = line.Trim();
                if (string.IsNullOrEmpty(trimmed) || trimmed.StartsWith('#')) continue;
                result.EndpointsTested++;

                if (IsHashFormat(trimmed))
                {
                    var parts = trimmed.Split(':', 2);
                    var hash = parts[0].Trim();
                    var plaintext = parts.Length > 1 ? parts[1].Trim() : null;
                    await AuditPasswordHashAsync(hash, plaintext, filePath, result);
                }
                else
                {
                    await AuditSinglePasswordAsync(trimmed, result, filePath);
                }
            }
        }
        catch (Exception ex) { Logger.Debug($"Error reading file {filePath}: {ex.Message}"); }
    }

    private static bool IsHashFormat(string input)
    {
        var hashPart = input.Contains(':') ? input[..input.IndexOf(':')] : input;
        hashPart = hashPart.Trim();
        return Regex.IsMatch(hashPart, @"^[a-fA-F0-9]{32,128}$") ||
               Regex.IsMatch(hashPart, @"^\$2[aby]\$") ||
               Regex.IsMatch(hashPart, @"^\$6\$") ||
               Regex.IsMatch(hashPart, @"^\$5\$");
    }

    private async Task AuditSinglePasswordAsync(string password, ScanResult result, string? sourceFile = null)
    {
        if (string.IsNullOrEmpty(password) || password.Length > MaxPasswordLength) return;

        var score = CalculateStrengthScore(password);
        var entropyBits = CalculateEntropyBits(password);
        var commonPatterns = FindCommonPatterns(password);
        var isCommon = _commonPasswords.Contains(password);
        var crackTime = EstimateBruteForceTime(entropyBits);

        var findings = new List<string>();
        if (score < 30) findings.Add("Extremely weak password");
        else if (score < 50) findings.Add("Weak password");
        else if (score < 70) findings.Add("Moderate password");
        else if (score < 85) findings.Add("Strong password");
        else findings.Add("Very strong password");

        if (isCommon) findings.Add("Found in common password list");
        if (commonPatterns.Count > 0) findings.Add($"Contains common patterns: {string.Join(", ", commonPatterns)}");
        if (password.Length < 8) findings.Add("Too short (< 8 characters)");
        if (entropyBits < 28) findings.Add($"Very low entropy ({entropyBits:F1} bits)");

        var severity = score switch { < 30 => "Critical", < 50 => "High", < 70 => "Medium", _ => "Info" };
        var description = $"Password score: {score}/100 | Entropy: {entropyBits:F1} bits | Crack time: {crackTime} | {string.Join("; ", findings)}";

        var vuln = new Vulnerability
        {
            Type = "Password Audit", Severity = severity, Url = sourceFile ?? "direct-input",
            Parameter = "Password", Payload = new string('*', Math.Min(password.Length, 20)),
            Description = description,
            Evidence = $"Length: {password.Length} | HasUpper: {password.Any(char.IsUpper)} | HasLower: {password.Any(char.IsLower)} | HasDigit: {password.Any(char.IsDigit)} | HasSpecial: {HasSpecialChar(password)} | Entropy: {entropyBits:F1} bits",
            Remediation = BuildRemediation(score, password.Length, commonPatterns),
            Module = "PasswordAuditor", Confidence = 100
        };
        result.Vulnerabilities.Add(vuln);
        Logger.LogVulnerability(vuln);

        await CheckHaveIBeenPwnedAsync(password, result, sourceFile, score, entropyBits);
        result.RequestsSent++;
    }

    private async Task AuditPasswordHashAsync(string hash, string? plaintext, string sourceFile, ScanResult result)
    {
        var hashType = IdentifyHashType(hash);
        result.Vulnerabilities.Add(new Vulnerability
        {
            Type = "Password Hash Detected", Severity = "Info", Url = sourceFile,
            Parameter = "Hash", Payload = hash.Length > 40 ? hash[..20] + "..." + hash[^20..] : hash,
            Description = plaintext != null ? $"Hash {hashType} with known plaintext — checking for exposure." : $"Hash {hashType} found. Cannot be checked against HIBP without plaintext.",
            Evidence = $"Type: {hashType}",
            Remediation = plaintext == null ? "Provide plaintext alongside the hash (hash:plaintext format) for HIBP checking." : "Ensure plaintext passwords are stored securely and not alongside their hashes.",
            Module = "PasswordAuditor", Confidence = 100
        });

        if (plaintext != null)
            await AuditSinglePasswordAsync(plaintext, result, sourceFile);

        await Task.CompletedTask;
    }

    private static string IdentifyHashType(string hash)
    {
        if (hash.StartsWith("$2a$") || hash.StartsWith("$2b$") || hash.StartsWith("$2y$")) return "bcrypt";
        if (hash.StartsWith("$6$")) return "SHA-512 crypt";
        if (hash.StartsWith("$5$")) return "SHA-256 crypt";
        if (hash.StartsWith("$1$")) return "MD5 crypt";
        return hash.Length switch { 32 => "MD5 (likely)", 40 => "SHA-1 (likely)", 56 => "SHA-224 (likely)", 64 => "SHA-256 (likely)", 96 => "SHA-384 (likely)", 128 => "SHA-512 (likely)", _ => "Unknown" };
    }

    private static async Task CheckHaveIBeenPwnedAsync(string password, ScanResult result, string? sourceFile, int score, double entropyBits)
    {
        try
        {
            var sha1Hash = ComputeSha1Hash(password);
            var prefix = sha1Hash[..5];
            var suffix = sha1Hash[5..];
            var response = await _hibpClient.GetAsync($"{HibpApiBase}{prefix}");
            if (response.IsSuccessStatusCode)
            {
                var body = await response.Content.ReadAsStringAsync();
                foreach (var line in body.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                {
                    var parts = line.Split(':');
                    if (parts.Length == 2 && parts[0].Trim().Equals(suffix, StringComparison.OrdinalIgnoreCase))
                    {
                        var count = int.TryParse(parts[1].Trim(), out var c) ? c : 0;
                        var severity = count switch { > 1000000 => "Critical", > 100000 => "High", > 1000 => "Medium", > 10 => "Low", _ => "Info" };
                        var description = count > 0 ? $"This password has been exposed in {count:N0} data breaches! Found in HIBP database." : "Password suffix matched in HIBP but count was zero.";
                        result.Vulnerabilities.Add(new Vulnerability
                        {
                            Type = "HaveIBeenPwned: Password Exposed", Severity = severity, Url = sourceFile ?? "direct-input",
                            Parameter = "HIBP", Payload = $"Hash prefix: {prefix} (k-anonymous)", Description = description,
                            Evidence = $"Exposure count: {count:N0} | Password score: {score}/100 | Entropy: {entropyBits:F1} bits",
                            Remediation = "Change this password immediately on all services where it is used. Never reuse breached passwords.",
                            Module = "PasswordAuditor", Confidence = 100
                        });
                        Logger.LogVulnerability(result.Vulnerabilities[^1]);
                        return;
                    }
                }
                Logger.Debug($"Password not found in HIBP (prefix {prefix} checked via k-anonymity).");
            }
        }
        catch (HttpRequestException ex) { Logger.Debug($"HIBP check failed (network): {ex.Message}"); }
        catch (TaskCanceledException) { Logger.Debug("HIBP check timed out."); }
        catch (Exception ex) { Logger.Debug($"HIBP check error: {ex.Message}"); }
    }

    public int CalculateStrengthScore(string password)
    {
        if (string.IsNullOrEmpty(password)) return 0;
        var score = 0;
        score += Math.Min(password.Length * 3, 40);
        if (password.Any(char.IsUpper)) score += 10;
        if (password.Any(char.IsLower)) score += 10;
        if (password.Any(char.IsDigit)) score += 10;
        if (HasSpecialChar(password)) score += 10;

        var patternPenalty = 0;
        foreach (var pattern in _commonPatterns)
        {
            if (password.Contains(pattern, StringComparison.OrdinalIgnoreCase)) { patternPenalty += 5; if (patternPenalty >= 30) break; }
        }
        score -= patternPenalty;
        if (_commonPasswords.Contains(password)) score -= 40;
        if (HasExcessiveRepeats(password)) score -= 15;
        if (HasSequentialChars(password)) score -= 15;
        if (password.All(char.IsLetter) && password.Length < 6) score -= 20;
        return Math.Clamp(score, 0, 100);
    }

    public static double CalculateEntropyBits(string password)
    {
        if (string.IsNullOrEmpty(password)) return 0;
        var poolSize = 0;
        if (password.Any(char.IsLower)) poolSize += 26;
        if (password.Any(char.IsUpper)) poolSize += 26;
        if (password.Any(char.IsDigit)) poolSize += 10;
        if (HasSpecialChar(password)) poolSize += 33;
        if (poolSize == 0) poolSize = 26;
        return password.Length * Math.Log2(poolSize);
    }

    public static string EstimateBruteForceTime(double entropyBits)
    {
        const double guessesPerSecond = 1_000_000_000;
        var combinations = Math.Pow(2, entropyBits);
        var seconds = combinations / guessesPerSecond;
        return seconds switch
        {
            < 0.001 => "Instant", < 1 => $"{seconds * 1000:F0} ms", < 60 => $"{seconds:F0} seconds",
            < 3600 => $"{seconds / 60:F1} minutes", < 86400 => $"{seconds / 3600:F1} hours",
            < 365 * 86400 => $"{seconds / 86400:F1} days",
            < 365L * 86400 * 100 => $"{seconds / (365.0 * 86400):F1} years",
            < 365L * 86400 * 1000 => $"{seconds / (365.0 * 86400):F0} years", _ => "Centuries+"
        };
    }

    private List<string> FindCommonPatterns(string password)
    {
        var found = new List<string>();
        foreach (var pattern in _commonPatterns)
            if (password.Contains(pattern, StringComparison.OrdinalIgnoreCase)) found.Add(pattern);
        if (Regex.IsMatch(password, @"\b(19|20)\d{2}\b")) found.Add("year");
        if (Regex.IsMatch(password, @"\b\d{1,2}[-/]\d{1,2}\b")) found.Add("date");
        return found;
    }

    private static bool HasSpecialChar(string password) => password.Any(c => !char.IsLetterOrDigit(c) && !char.IsWhiteSpace(c));

    private static bool HasExcessiveRepeats(string password)
    {
        if (password.Length < 4) return false;
        for (int i = 0; i < password.Length - 3; i++)
            if (password[i] == password[i + 1] && password[i] == password[i + 2] && password[i] == password[i + 3]) return true;
        return false;
    }

    private static bool HasSequentialChars(string password)
    {
        if (password.Length < 4) return false;
        for (int i = 0; i < password.Length - 3; i++)
        {
            if (password[i + 1] == password[i] + 1 && password[i + 2] == password[i] + 2 && password[i + 3] == password[i] + 3) return true;
            if (password[i + 1] == password[i] - 1 && password[i + 2] == password[i] - 2 && password[i + 3] == password[i] - 3) return true;
        }
        return false;
    }

    private static string BuildRemediation(int score, int length, List<string> patterns)
    {
        var tips = new List<string>();
        if (length < 12) tips.Add("use at least 12 characters");
        if (!patterns.Any(p => p.Any(char.IsDigit))) tips.Add("avoid predictable sequences like '1234' or 'qwerty'");
        if (score < 70) tips.Add("use a mix of uppercase, lowercase, numbers, and special characters");
        if (score < 50) tips.Add("consider using a password manager to generate and store strong passwords");
        return tips.Count > 0 ? "Password improvement needed: " + string.Join("; ", tips) + "." : "Password is strong. Consider rotating it periodically.";
    }

    private static string ComputeSha1Hash(string input)
    {
        var bytes = Encoding.UTF8.GetBytes(input);
        return Convert.ToHexString(SHA1.HashData(bytes));
    }
}
