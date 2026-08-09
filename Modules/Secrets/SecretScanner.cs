using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using SecKit.Core;
using SecKit.Models;

namespace SecKit.Modules.Secrets;

/// <summary>
/// Scans files and directories for hardcoded secrets using regex patterns,
/// entropy analysis, and common secret-file detection.
/// </summary>
public class SecretScanner
{
    private readonly ConfigManager _config;
    private readonly (string Type, string Pattern, string Severity)[] _secretPatterns;
    private readonly string[] _secretFilePatterns;
    private readonly HashSet<string> _textExtensions;

    // ── Default regex patterns (used only if config is empty) ──
    private static readonly (string Type, string Pattern, string Severity)[] DefaultSecretPatterns =
    {
        ("AWS Access Key",     @"AKIA[0-9A-Z]{16}",                                                           "Critical"),
        ("GitHub Token (classic)",  @"ghp_[A-Za-z0-9]{36}",                                                   "Critical"),
        ("GitHub Token (fine-grained)", @"github_pat_[A-Za-z0-9_]{82,}",                                      "Critical"),
        ("Slack Webhook",      @"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",      "Critical"),
        ("Stripe Live Key",    @"sk_live_[A-Za-z0-9]{24,99}",                                                 "Critical"),
        ("Stripe Test Key",    @"sk_test_[A-Za-z0-9]{24,99}",                                                 "High"),
        ("Google API Key",     @"AIza[0-9A-Za-z\-_]{35}",                                                     "High"),
        ("JWT Secret",         @"(eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)",                 "High"),
        ("Connection String (SQL)",  @"(Server|Data Source|Initial Catalog|Database|User ID|Password)\s*=.+",   "High"),
        ("Connection String (Mongo)",@"mongodb(?:\+srv)?://[^/\s""<]+",                                       "Critical"),
        ("Connection String (Postgres)", @"postgres(?:ql)?://[^/\s""<]+",                                     "Critical"),
        ("Private Key (RSA)",  @"-----BEGIN RSA PRIVATE KEY-----",                                            "Critical"),
        ("Private Key (EC)",   @"-----BEGIN EC PRIVATE KEY-----",                                             "Critical"),
        ("Private Key (DSA)",  @"-----BEGIN DSA PRIVATE KEY-----",                                            "Critical"),
        ("Private Key (OpenSSH)", @"-----BEGIN OPENSSH PRIVATE KEY-----",                                     "Critical"),
        ("Generic Private Key",@"-----BEGIN PRIVATE KEY-----",                                                "Critical"),
        (".env Assignment",    @"^\s*[A-Za-z0-9_]+\s*=\s*['""]?[^'""\n]{8,}['""]?\s*$",                      "High"),
        ("Bearer Token",       @"Bearer\s+[A-Za-z0-9\-_\.]{20,}",                                            "High"),
        ("Basic Auth",         @"Basic\s+[A-Za-z0-9+/=]{20,}",                                               "High"),
        ("Generic Password Assignment", @"(?:password|passwd|pwd|api_key|apikey|secret|token)\s*[:=]\s*['""]?[^'""\n\r]{6,}['""]?", "High"),
    };

    private const int DefaultMaxDepth = 10;
    private const double EntropyThreshold = 4.0;
    private const int MaxFileSizeBytes = 10 * 1024 * 1024; // 10 MB

    public SecretScanner(ConfigManager config)
    {
        _config = config;

        // Load secret patterns from config, fall back to defaults
        var configuredPatterns = config.SecretPatterns;
        _secretPatterns = configuredPatterns.Count > 0
            ? configuredPatterns.Select(p => (p.Type, p.Pattern, p.Severity)).ToArray()
            : DefaultSecretPatterns;

        _secretFilePatterns = config.SecretFilePatterns.ToArray();
        _textExtensions = new HashSet<string>(config.SecretFileExtensions, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>Scans the specified path (file or directory) for hardcoded secrets.</summary>
    public async Task<ScanResult> ScanAsync(string target)
    {
        var result = new ScanResult
        {
            ModuleName = "Secret Scanner",
            TargetUrl = target,
            StartTime = DateTime.UtcNow
        };

        try
        {
            var path = ResolvePath(target);

            if (!Directory.Exists(path) && !File.Exists(path))
            {
                result.ErrorMessage = $"Path does not exist: {path}";
                Logger.Error(result.ErrorMessage);
                result.Completed = true;
                result.EndTime = DateTime.UtcNow;
                return result;
            }

            Logger.Info($"Scanning for secrets in: {path}");

            if (File.Exists(path))
            {
                await ScanFileAsync(path, result);
                result.EndpointsTested = 1;
            }
            else
            {
                var files = GetFilesToScan(path);
                result.EndpointsTested = files.Count;
                Logger.Info($"Found {files.Count} files to scan");

                foreach (var file in files)
                {
                    await ScanFileAsync(file, result);
                }
            }

            result.Completed = true;
        }
        catch (Exception ex)
        {
            result.ErrorMessage = ex.Message;
            Logger.Error($"Secret scanner failed: {ex.Message}");
        }

        result.EndTime = DateTime.UtcNow;
        return result;
    }

    private static string ResolvePath(string target)
    {
        var path = target;
        if (!Path.IsPathRooted(path))
            path = Path.GetFullPath(path);
        return path;
    }

    private List<string> GetFilesToScan(string rootPath)
    {
        var files = new List<string>();

        try
        {
            foreach (var pattern in _secretFilePatterns)
            {
                try
                {
                    if (pattern.Contains(".*"))
                    {
                        var baseName = pattern[..pattern.IndexOf(".*")];
                        var found = Directory.GetFiles(rootPath, baseName + ".*", SearchOption.AllDirectories);
                        files.AddRange(found);
                    }
                    else
                    {
                        var found = Directory.GetFiles(rootPath, pattern, SearchOption.AllDirectories);
                        files.AddRange(found);
                    }
                }
                catch (UnauthorizedAccessException) { Logger.Debug($"Access denied for pattern: {pattern}"); }
                catch (DirectoryNotFoundException) { }
            }

            try
            {
                foreach (var ext in _textExtensions)
                {
                    try
                    {
                        var found = Directory.GetFiles(rootPath, "*" + ext,
                            new EnumerationOptions
                            {
                                RecurseSubdirectories = true,
                                MaxRecursionDepth = Math.Min(DefaultMaxDepth, _config.MaxDepth > 0 ? _config.MaxDepth : DefaultMaxDepth),
                                IgnoreInaccessible = true
                            });

                        foreach (var f in found)
                        {
                            if (!files.Contains(f))
                                files.Add(f);
                        }
                    }
                    catch { }
                }
            }
            catch { }

            files = files.Distinct().ToList();
        }
        catch (Exception ex)
        {
            Logger.Debug($"File collection error: {ex.Message}");
        }

        return files;
    }

    private async Task ScanFileAsync(string filePath, ScanResult result)
    {
        try
        {
            var fileInfo = new FileInfo(filePath);
            if (!fileInfo.Exists || fileInfo.Length > MaxFileSizeBytes)
                return;

            var lines = await File.ReadAllLinesAsync(filePath);
            var fileName = fileInfo.Name;

            for (int i = 0; i < lines.Length; i++)
            {
                var line = lines[i];
                if (string.IsNullOrWhiteSpace(line)) continue;

                foreach (var (type, pattern, severity) in _secretPatterns)
                {
                    var matches = Regex.Matches(line, pattern, RegexOptions.Compiled);
                    foreach (Match m in matches)
                    {
                        if (m.Value.Length < 6) continue;

                        var preview = RedactPreview(m.Value);

                        result.Vulnerabilities.Add(new Vulnerability
                        {
                            Type = $"Hardcoded Secret: {type}",
                            Severity = severity,
                            Url = filePath,
                            Parameter = $"Line {i + 1}",
                            Payload = preview,
                            Description = $"Found {type} in {fileName} at line {i + 1}: {preview}",
                            Evidence = line.Trim().Length > 300 ? line.Trim()[..300] + "..." : line.Trim(),
                            Remediation = $"Remove hardcoded {type}. Use environment variables, secure vaults, or secret management services.",
                            Module = "SecretScanner",
                            Confidence = severity == "Critical" ? 95 : 80
                        });

                        Logger.LogVulnerability(result.Vulnerabilities[^1]);
                    }
                }

                var entropyCandidates = ExtractHighEntropyStrings(line);
                foreach (var candidate in entropyCandidates)
                {
                    if (result.Vulnerabilities.Any(v => v.Payload != null && v.Payload.Contains(RedactPreview(candidate))))
                        continue;

                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = "Suspicious High-Entropy String",
                        Severity = "Medium",
                        Url = filePath,
                        Parameter = $"Line {i + 1}",
                        Payload = RedactPreview(candidate),
                        Description = $"High-entropy string ({candidate.Length} chars) found in {fileName} at line {i + 1}: {RedactPreview(candidate)}. May be a hardcoded secret.",
                        Evidence = line.Trim().Length > 300 ? line.Trim()[..300] + "..." : line.Trim(),
                        Remediation = "Review this string. If it is a secret, remove it from source code and use a secrets manager.",
                        Module = "SecretScanner",
                        Confidence = 50
                    });
                }

                if ((fileName.StartsWith(".env") || line.Contains('=')) && !line.TrimStart().StartsWith("#"))
                {
                    var eqIdx = line.IndexOf('=');
                    if (eqIdx > 0 && eqIdx < line.Length - 4)
                    {
                        var key = line[..eqIdx].Trim();
                        var val = line[(eqIdx + 1)..].Trim().Trim('\'', '"');

                        if (val.Length >= 8 && IsSensitiveKey(key))
                        {
                            if (!result.Vulnerabilities.Any(v => v.Parameter == $"Line {i + 1}" && v.Type.Contains(key, StringComparison.OrdinalIgnoreCase)))
                            {
                                result.Vulnerabilities.Add(new Vulnerability
                                {
                                    Type = $"Hardcoded Secret: {key}",
                                    Severity = "High",
                                    Url = filePath,
                                    Parameter = $"Line {i + 1}",
                                    Payload = RedactPreview(val),
                                    Description = $"Environment variable '{key}' has a value set in {fileName} at line {i + 1}: {RedactPreview(val)}",
                                    Evidence = line.Trim().Length > 300 ? line.Trim()[..300] + "..." : line.Trim(),
                                    Remediation = "Move sensitive environment variables out of committed files. Use .env.example with placeholder values.",
                                    Module = "SecretScanner",
                                    Confidence = 85
                                });
                            }
                        }
                    }
                }
            }

            result.RequestsSent++;
        }
        catch (UnauthorizedAccessException)
        {
            Logger.Debug($"Access denied: {filePath}");
        }
        catch (Exception ex)
        {
            Logger.Debug($"Error scanning {filePath}: {ex.Message}");
        }

        await Task.CompletedTask;
    }

    private static string RedactPreview(string value)
    {
        if (value.Length <= 8)
            return new string('*', value.Length);
        return value[..4] + new string('*', Math.Min(value.Length - 8, 20)) + value[^4..];
    }

    private static bool IsSensitiveKey(string key)
    {
        var lower = key.ToLowerInvariant();
        return lower.Contains("key") || lower.Contains("secret") || lower.Contains("token") ||
               lower.Contains("password") || lower.Contains("passwd") || lower.Contains("pwd") ||
               lower.Contains("auth") || lower.Contains("credential") || lower.Contains("private") ||
               lower.Contains("cert") || lower.Contains("jwt") || lower.Contains("api") ||
               lower.Contains("dsn") || lower.Contains("connection") || lower.Contains("access") ||
               lower.Contains("smtp") || lower.Contains("s3") || lower.Contains("aws") ||
               lower.Contains("sentry") || lower.Contains("datadog") || lower.Contains("new_relic");
    }

    private static List<string> ExtractHighEntropyStrings(string line)
    {
        var candidates = new List<string>();
        var tokens = Regex.Split(line, @"[\s,;""'`()\[\]{}<>:&|!]+")
            .Where(t => t.Length >= 16 && t.Length <= 256)
            .Where(t => !t.StartsWith("http") && !t.StartsWith("/") && !t.StartsWith("."));

        foreach (var token in tokens)
        {
            if (CalculateShannonEntropy(token) > EntropyThreshold)
                candidates.Add(token);
        }
        return candidates;
    }

    private static double CalculateShannonEntropy(string input)
    {
        if (string.IsNullOrEmpty(input)) return 0;
        var frequencies = new Dictionary<char, int>();
        foreach (var c in input)
        {
            frequencies.TryGetValue(c, out var count);
            frequencies[c] = count + 1;
        }
        double entropy = 0;
        var length = (double)input.Length;
        foreach (var freq in frequencies.Values)
        {
            var probability = freq / length;
            entropy -= probability * Math.Log2(probability);
        }
        return entropy;
    }
}
