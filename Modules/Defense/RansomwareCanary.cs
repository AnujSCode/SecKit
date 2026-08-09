using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using SecKit.Core;
using SecKit.Models;

namespace SecKit.Modules.Defense;

/// <summary>
/// Deploys and monitors canary (honeypot) files to detect ransomware activity.
/// Creates bait files with known content, periodically checks for modifications,
/// entropy spikes, mass renames, and ransom notes. Rate-limits alerts to avoid noise.
/// </summary>
public class RansomwareCanary
{
    /// <summary>Default constructor.</summary>
    public RansomwareCanary() { }

    /// <summary>Constructor with configuration.</summary>
    public RansomwareCanary(ConfigManager config) { }

    // Known-good hashes for deployed canary files
    private static readonly Dictionary<string, string> CanaryHashes = new(StringComparer.Ordinal);

    // Ransomware note filename patterns
    private static readonly string[] RansomNotePatterns =
    {
        "README*", "DECRYPT*", "HELP_DECRYPT*", "HOW_TO_DECRYPT*",
        "RECOVER*", "RESTORE*", "YOUR_FILES*", "DECRYPTION*",
        "RANSOM*", "RANSOMWARE*", "RANSOM_NOTE*", "!!!READ_ME!!!",
        "FILES_ENCRYPTED*", "HOW_TO_RECOVER*", "!!!HOW_TO_DECRYPT!!!",
        "_readme*", "_DECRYPT*", "_RECOVER*", "!!!DECRYPTION!!!"
    };

    // Known ransomware extensions
    private static readonly string[] RansomExtensions =
    {
        ".ransom", ".encrypted", ".locked", ".crypt", ".crypto",
        ".locky", ".zepto", ".odin", ".thor", ".paym", ".wallet",
        ".onion", ".cerber", ".dharma", ".phobos", ".stop", ".djvu",
        ".mamba", ".blackcat", ".lockbit", ".hive", ".conti",
        ".XXX", ".MOLE", ".enc", ".ENCRYPTED", ".id[X", ".id-",
        ".email=", ".decrypt2017", ".WannaCry", ".WannaCrypto",
        ".wcry", ".WNCRY", ".WNCRYT", ".no_more_ransom",
        ".encryptedRSA", ".cry", ".crinf", ".r5a", ".XRNT",
        ".CTBL", ".Crypted", ".pzdc", ".good", ".CHAK", ".KEYPASS",
        ".KEYH0LES", ".crypton", ".ezz", ".ecc", ".abc", ".towel",
        ".zzzzz", ".xxx", ".xyz", ".aaa", ".micro", ".ttt",
        ".kraken", ".shade", ".bloc", ".aes", ".mich",
        ".breaking_bad", ".heisenberg", ".bart", ".zepto",
        ".lock93", ".dharma", ".wallet", ".onion3", ".bip", ".gamma",
        ".nuclear", ".hydra", ".wasted", ".maktub", "_crypt"
    };

    // Alert tracking to rate-limit notifications
    private readonly Dictionary<string, DateTime> _alertCooldowns = new(StringComparer.Ordinal);
    private static readonly TimeSpan AlertCooldownInterval = TimeSpan.FromMinutes(5);
    private DateTime _lastMassRenameAlert = DateTime.MinValue;
    private static readonly TimeSpan MassRenameAlertCooldown = TimeSpan.FromMinutes(10);

    /// <summary>
    /// Runs the ransomware canary scan: deploys canary files if needed,
    /// then monitors for signs of ransomware activity.
    /// </summary>
    /// <param name="target">Comma-separated list of directories to protect, or "auto" for defaults.</param>
    /// <returns>ScanResult with ransomware canary findings.</returns>
    public async Task<ScanResult> ScanAsync(string target)
    {
        var result = new ScanResult
        {
            ModuleName = "Ransomware Canary",
            TargetUrl = target,
            StartTime = DateTime.UtcNow
        };

        try
        {
            var directories = ParseDirectories(target);
            Logger.Info($"Ransomware Canary: monitoring {directories.Count} directories...");

            var deployed = 0;
            foreach (var dir in directories)
            {
                deployed += await DeployCanaryFilesAsync(dir, result);
            }
            Logger.Info($"Deployed {deployed} canary files across {directories.Count} directories.");

            await Task.WhenAll(
                CheckCanaryIntegrityAsync(directories, result),
                CheckForRansomNotesAsync(directories, result),
                CheckForMassRenamesAsync(directories, result),
                CheckEntropyAnomaliesAsync(directories, result)
            );

            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "Ransomware Canary Status",
                Severity = "Info",
                Description = $"Ransomware canary active: {CanaryHashes.Count} canary files deployed across {directories.Count} directories.",
                Remediation = "Review any security alerts and investigate suspicious activity.",
                Evidence = $"Canary count: {CanaryHashes.Count} | Directories: {directories.Count}",
                Module = "RansomwareCanary",
                Confidence = 95
            });

            result.Completed = true;
            Logger.Info($"Ransomware canary scan complete: {result.Vulnerabilities.Count} findings.");
        }
        catch (Exception ex)
        {
            result.ErrorMessage = ex.Message;
            Logger.Error($"Ransomware canary failed: {ex.Message}");
        }

        result.EndTime = DateTime.UtcNow;
        return result;
    }

    private static List<string> ParseDirectories(string target)
    {
        if (string.IsNullOrWhiteSpace(target) || target.Equals("auto", StringComparison.OrdinalIgnoreCase))
        {
            return new List<string> { "/home", "/root", "/var/www", "/srv", "/opt", "/tmp/seckit-canary" }
                .Where(d => Directory.Exists(d) || d.StartsWith("/tmp"))
                .ToList();
        }
        return target.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries)
            .Select(d => d.Trim())
            .Where(d => Directory.Exists(d) || d.StartsWith("/tmp"))
            .ToList();
    }

    private async Task<int> DeployCanaryFilesAsync(string directory, ScanResult result)
    {
        var count = 0;
        var canaryDir = Path.Combine(directory, ".seckit_canary");

        try
        {
            if (!Directory.Exists(canaryDir))
            {
                Directory.CreateDirectory(canaryDir);
                Logger.Debug($"Created canary directory: {canaryDir}");
                try { File.SetAttributes(canaryDir, FileAttributes.Hidden | FileAttributes.Directory); }
                catch { }
            }

            var filesToDeploy = new (string Name, string Content)[]
            {
                ("invoice_canary.pdf",
                    "%PDF-1.7\n%âãÏÓ\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n" +
                    "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n" +
                    "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n" +
                    "xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n" +
                    "0000000115 00000 n \ntrailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n190\n%%EOF\n" +
                    "SECKIT CANARY FILE — DO NOT MODIFY OR REMOVE\n" +
                    $"Deployed: {DateTime.UtcNow:O}\n"),
                ("document_canary.docx",
                    "PK\u0003\u0004\u0014\u0000\u0000\u0000\u0000\u0000SECKIT CANARY DOCX\n" +
                    "[Content_Types].xml\n<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                    "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\n" +
                    "  <Default Extension=\"xml\" ContentType=\"application/xml\"/>\n" +
                    "</Types>\nSECKIT CANARY — DO NOT MODIFY\n"),
                ("notes_canary.txt",
                    "SECRET CANARY FILE — DO NOT MODIFY\n" +
                    $"Deployed: {DateTime.UtcNow:O}\n" +
                    "Monitored by SecKit Ransomware Canary v3.0\n" +
                    "Any modification to this file triggers an alert.\n"),
                ("photo_canary.jpg",
                    "\u00FF\u00D8\u00FF\u00E0\u0000\u0010JFIF\u0000\u0001\u0001\u0000\u0000\u0001\u0000\u0001\u0000\u0000" +
                    "\u00FF\u00DB\u0000\u0043\u0000\u0008\u0006\u0006\u0007\u0006\u0005\u0008\u0007\u0007\u0007\t\t" +
                    "SECKIT CANARY JPEG — DO NOT MODIFY\n" +
                    $"Deployed: {DateTime.UtcNow:O}\n\u00FF\u00D9"),
                ("config_canary.json",
                    "{\n  \"canary\": true,\n  \"version\": \"3.0\",\n" +
                    $"  \"deployed\": \"{DateTime.UtcNow:O}\",\n" +
                    "  \"monitor\": \"SecKit\",\n" +
                    "  \"secret\": \"NCx7kQp3mZ9vL2bRf8hY\"\n}\n"),
                ("spreadsheet_canary.xlsx",
                    "PK\u0003\u0004\u0014\u0000\u0000\u0000\u0000\u0000SECKIT CANARY XLSX\n" +
                    "xl/workbook.xml\n<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                    "<workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\">\n" +
                    "  <sheets><sheet name=\"Canary\" sheetId=\"1\"/></sheets>\n" +
                    "</workbook>\nSECKIT CANARY — DO NOT MODIFY\n"),
                ("database_canary.sqlite",
                    "SQLite format 3\u0000\u0010\u0000\u0001\u0001\u0000@  \u0000" +
                    "SECKIT CANARY SQLITE DB\n" +
                    "TABLE canary (id INTEGER PRIMARY KEY, secret TEXT);\n" +
                    $"INSERT INTO canary VALUES (1, 'NCx7kQp3mZ9vL2bRf8hY');\n"),
                ("script_canary.sh",
                    "#!/bin/bash\n# SECKIT CANARY — DO NOT REMOVE\n" +
                    "echo \"This is a canary file for ransomware detection.\"\nexit 0\n"),
            };

            foreach (var (name, content) in filesToDeploy)
            {
                var filePath = Path.Combine(canaryDir, name);
                if (File.Exists(filePath))
                {
                    var currentHash = await ComputeSha256Async(filePath);
                    CanaryHashes[filePath] = currentHash;
                    Logger.Debug($"Canary exists: {filePath} (hash: {currentHash[..Math.Min(16, currentHash.Length)]}...)");
                }
                else
                {
                    await File.WriteAllTextAsync(filePath, content);
                    var hash = await ComputeSha256Async(filePath);
                    CanaryHashes[filePath] = hash;
                    count++;
                    Logger.Debug($"Deployed canary: {filePath} (hash: {hash[..Math.Min(16, hash.Length)]}...)");
                }
            }
        }
        catch (Exception ex)
        {
            Logger.Warning($"Failed to deploy canary files in {directory}: {ex.Message}");
            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "Canary Deployment Failure",
                Severity = "Low",
                Description = $"Failed to deploy canary files in '{directory}': {ex.Message}",
                Remediation = "Check directory permissions and disk space.",
                Evidence = directory,
                Module = "RansomwareCanary",
                Confidence = 90
            });
        }

        return count;
    }

    /// <summary>Checks deployed canary files against known-good hashes.</summary>
    private async Task CheckCanaryIntegrityAsync(List<string> directories, ScanResult result)
    {
        try
        {
            var modified = new List<string>();
            var deleted = new List<string>();
            var now = DateTime.UtcNow;

            foreach (var (filePath, knownHash) in CanaryHashes)
            {
                if (!File.Exists(filePath))
                {
                    deleted.Add(filePath);
                }
                else
                {
                    var currentHash = await ComputeSha256Async(filePath);
                    if (!string.Equals(currentHash, knownHash, StringComparison.Ordinal))
                        modified.Add(filePath);
                }
            }

            foreach (var file in deleted)
            {
                var alertKey = $"deleted:{file}";
                if (!ShouldAlert(alertKey, now)) continue;
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "Ransomware Canary Deleted",
                    Severity = "Critical",
                    Description = $"CRITICAL: Canary file DELETED: '{file}'. Possible ransomware activity.",
                    Remediation = "Immediately disconnect from network. Check for ransomware. Restore from backups.",
                    Evidence = $"Deleted: {file}",
                    Module = "RansomwareCanary",
                    Confidence = 85
                });
                Logger.Critical($"RANSOMWARE ALERT: Canary deleted: {file}");
            }

            foreach (var file in modified)
            {
                var alertKey = $"modified:{file}";
                if (!ShouldAlert(alertKey, now)) continue;
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "Ransomware Canary Modified",
                    Severity = "Critical",
                    Description = $"CRITICAL: Canary file MODIFIED: '{file}'. Possible ransomware encryption.",
                    Remediation = "Immediately disconnect from network. Check for ransomware indicators.",
                    Evidence = $"Modified: {file}",
                    Module = "RansomwareCanary",
                    Confidence = 85
                });
                Logger.Critical($"RANSOMWARE ALERT: Canary modified: {file}");
            }

            Logger.Debug($"Integrity check: {CanaryHashes.Count - modified.Count - deleted.Count} OK, " +
                        $"{modified.Count} modified, {deleted.Count} deleted.");
        }
        catch (Exception ex)
        {
            Logger.Debug($"Canary integrity check failed: {ex.Message}");
        }
    }

    /// <summary>Scans for ransom note files and encrypted file extensions.</summary>
    private async Task CheckForRansomNotesAsync(List<string> directories, ScanResult result)
    {
        try
        {
            var foundNotes = new List<string>();
            foreach (var dir in directories)
            {
                if (!Directory.Exists(dir)) continue;
                foreach (var pattern in RansomNotePatterns)
                {
                    try
                    {
                        var escapedDir = dir.Replace("'", "'\\''");
                        var escapedPattern = pattern.Replace("'", "'\\''");
                        var output = await RunCommandAsync(
                            $"find '{escapedDir}' -maxdepth 3 -name '{escapedPattern}' -type f 2>/dev/null");
                        if (!string.IsNullOrWhiteSpace(output))
                            foundNotes.AddRange(output.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(f => f.Trim()));
                    }
                    catch { }
                }
                try
                {
                    var escapedDir = dir.Replace("'", "'\\''");
                    var extPatterns = string.Join(" -o -name '*", RansomExtensions.Select(e => e));
                    var output = await RunCommandAsync(
                        $"find '{escapedDir}' -maxdepth 2 \\( -name '*{extPatterns}' \\) -type f 2>/dev/null | head -50");
                    if (!string.IsNullOrWhiteSpace(output))
                        foundNotes.AddRange(output.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(f => f.Trim()));
                }
                catch { }
            }

            if (foundNotes.Count > 0)
            {
                var now = DateTime.UtcNow;
                var alertKey = $"ransom_notes:{foundNotes.Count}";
                if (ShouldAlert(alertKey, now))
                {
                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = "Ransomware Ransom Notes Detected",
                        Severity = "Critical",
                        Description = $"FOUND {foundNotes.Count} potential ransom notes/encrypted files. " +
                                      $"First 10: {string.Join(", ", foundNotes.Take(10))}",
                        Remediation = "SYSTEM LIKELY COMPROMISED. Isolate immediately. Do not pay ransom.",
                        Evidence = $"Ransom indicators: {string.Join("; ", foundNotes.Take(20))}",
                        Module = "RansomwareCanary",
                        Confidence = 90
                    });
                    Logger.Critical($"RANSOMWARE ALERT: {foundNotes.Count} ransom notes detected!");
                }
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"Ransom note check failed: {ex.Message}");
        }
    }

    /// <summary>Detects mass file renames characteristic of ransomware encryption.</summary>
    private async Task CheckForMassRenamesAsync(List<string> directories, ScanResult result)
    {
        try
        {
            var totalAffected = 0;
            foreach (var dir in directories)
            {
                if (!Directory.Exists(dir)) continue;
                foreach (var ext in RansomExtensions)
                {
                    try
                    {
                        var escapedDir = dir.Replace("'", "'\\''");
                        var escapedExt = ext.Replace("'", "'\\''");
                        var output = await RunCommandAsync(
                            $"find '{escapedDir}' -maxdepth 3 -name '*{escapedExt}' -type f 2>/dev/null | wc -l");
                        if (int.TryParse(output?.Trim(), out var count) && count > 0)
                            totalAffected += count;
                    }
                    catch { }
                }
            }

            if (totalAffected > 10)
            {
                var now = DateTime.UtcNow;
                if ((now - _lastMassRenameAlert) >= MassRenameAlertCooldown)
                {
                    _lastMassRenameAlert = now;
                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = "Mass File Renames (Ransomware)",
                        Severity = "Critical",
                        Description = $"Detected {totalAffected} files with known ransomware extensions. Active encryption in progress.",
                        Remediation = "IMMEDIATE ACTION: Isolate system. Identify encrypting process. Restore from clean backups.",
                        Evidence = $"Affected files: {totalAffected}",
                        Module = "RansomwareCanary",
                        Confidence = 95
                    });
                    Logger.Critical($"RANSOMWARE ALERT: {totalAffected} files with ransomware extensions!");
                }
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"Mass rename check failed: {ex.Message}");
        }
    }

    /// <summary>Performs entropy analysis — encrypted data has very high entropy (>7.0).</summary>
    private async Task CheckEntropyAnomaliesAsync(List<string> directories, ScanResult result)
    {
        try
        {
            foreach (var dir in directories)
            {
                if (!Directory.Exists(dir)) continue;
                try
                {
                    var escapedDir = dir.Replace("'", "'\\''");
                    var output = await RunCommandAsync(
                        $"find '{escapedDir}' -maxdepth 3 -type f -size +1k -size -10M 2>/dev/null | shuf -n 50");
                    if (string.IsNullOrWhiteSpace(output)) continue;

                    var files = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                    var highEntropyFiles = new List<(string Path, double Entropy)>();

                    foreach (var file in files)
                    {
                        var trimmed = file.Trim();
                        if (string.IsNullOrWhiteSpace(trimmed) || !File.Exists(trimmed)) continue;
                        var entropy = await ComputeShannonEntropyAsync(trimmed);
                        if (entropy > 7.0)
                            highEntropyFiles.Add((trimmed, entropy));
                    }

                    if (highEntropyFiles.Count > 3)
                    {
                        var now = DateTime.UtcNow;
                        var alertKey = $"entropy_spike:{dir}";
                        if (ShouldAlert(alertKey, now))
                        {
                            var examples = string.Join(", ", highEntropyFiles.Take(5)
                                .Select(f => $"{Path.GetFileName(f.Path)} (entropy: {f.Entropy:F2})"));
                            result.Vulnerabilities.Add(new Vulnerability
                            {
                                Type = "High File Entropy (Possible Encryption)",
                                Severity = "High",
                                Description = $"Detected {highEntropyFiles.Count} files with unusually high entropy (>7.0) " +
                                              $"in '{dir}'. Encrypted files have near-random byte distributions. Examples: {examples}",
                                Remediation = "Investigate whether files have been encrypted by ransomware.",
                                Evidence = $"High-entropy files: {highEntropyFiles.Count} in {dir}",
                                Module = "RansomwareCanary",
                                Confidence = 75
                            });
                            Logger.Warning($"Entropy alert: {highEntropyFiles.Count} high-entropy files in {dir}");
                        }
                    }
                }
                catch { }
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"Entropy analysis failed: {ex.Message}");
        }
    }

    /// <summary>Computes Shannon entropy of a file (0-8 scale).</summary>
    private static async Task<double> ComputeShannonEntropyAsync(string filePath)
    {
        try
        {
            var bytes = await File.ReadAllBytesAsync(filePath);
            if (bytes.Length == 0) return 0.0;
            var frequencies = new long[256];
            foreach (var b in bytes) frequencies[b]++;
            double entropy = 0.0;
            var total = (double)bytes.Length;
            for (int i = 0; i < 256; i++)
            {
                if (frequencies[i] > 0)
                {
                    var probability = frequencies[i] / total;
                    entropy -= probability * Math.Log2(probability);
                }
            }
            return entropy;
        }
        catch { return 0.0; }
    }

    /// <summary>Computes SHA-256 hash for integrity verification.</summary>
    private static async Task<string> ComputeSha256Async(string filePath)
    {
        try
        {
            using var sha256 = SHA256.Create();
            await using var stream = File.OpenRead(filePath);
            var hash = await sha256.ComputeHashAsync(stream);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }
        catch { return string.Empty; }
    }

    /// <summary>Rate-limits alerts to avoid noise.</summary>
    private bool ShouldAlert(string key, DateTime now)
    {
        if (_alertCooldowns.TryGetValue(key, out var lastAlert))
        {
            if ((now - lastAlert) < AlertCooldownInterval) return false;
        }
        _alertCooldowns[key] = now;
        return true;
    }

    /// <summary>Runs a shell command and returns stdout.</summary>
    private static async Task<string> RunCommandAsync(string command)
    {
        try
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "bash",
                    Arguments = $"-c \"{command.Replace("\"", "\\\"")}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };
            process.Start();
            var output = await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();
            return output;
        }
        catch (Exception ex)
        {
            Logger.Debug($"Command failed: {command} - {ex.Message}");
            return string.Empty;
        }
    }
}
