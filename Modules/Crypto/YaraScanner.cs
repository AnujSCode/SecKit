using System.Text;
using System.Text.RegularExpressions;
using System.Diagnostics;
using SecKit.Core;
using SecKit.Models;

namespace SecKit.Modules.Crypto;

/// <summary>
/// YARA-based file scanner that detects webshells, malware indicators, and sensitive data patterns.
/// Uses embedded regex-based rules when the YARA CLI is unavailable, with automatic fallback to
/// shelling out to the yara command-line tool when installed.
/// </summary>
public class YaraScanner
{
    private readonly ConfigManager _config;
    private readonly string _outputDir;
    private readonly bool _yaraCliAvailable;

    // ─── Embedded YARA-Compatible Rule Set ───

    /// <summary>Rule definition with name, pattern, description, and severity.</summary>
    private sealed record YaraRule(
        string Name,
        string Description,
        string Severity,
        int Confidence,
        Regex[] Patterns,
        string[] FileExtensions,
        string[]? Remediation);

    private static readonly YaraRule[] EmbeddedRules;

    static YaraScanner()
    {
        EmbeddedRules = new[]
        {
            // ─── Webshell Detection ───
            new YaraRule(
                "Webshell_Eval_Exec",
                "PHP webshell using eval/exec/system/passthru with user-controlled input",
                "Critical", 95,
                new[] {
                    // PHP eval with variable input
                    new Regex(@"\beval\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES|ENV)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                    // PHP exec with variable input
                    new Regex(@"\b(?:exec|system|passthru|shell_exec|popen|proc_open)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                    // PHP assert with user input
                    new Regex(@"\bassert\s*\(\s*\$_(?:GET|POST|REQUEST)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                    // PHP preg_replace /e modifier (deprecated but dangerous)
                    new Regex(@"preg_replace\s*\(\s*['""]/.*?/e['""]", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                },
                new[] { ".php", ".php3", ".php4", ".php5", ".php7", ".php8", ".phtml", ".pht" },
                new[] {
                    "Remove the webshell file immediately.",
                    "Audit all web server logs for access to this file.",
                    "Check for lateral movement or data exfiltration.",
                    "Harden PHP configuration: disable dangerous functions (disable_functions)."
                }
            ),
            new YaraRule(
                "Webshell_ASP_Exec",
                "ASP/ASPX webshell using Execute/Server.CreateObject for command execution",
                "Critical", 95,
                new[] {
                    new Regex(@"\bServer\.CreateObject\s*\(\s*""(?:WScript\.Shell|Scripting\.FileSystemObject|ADODB\.Stream)""", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                    new Regex(@"\bExecute\s*\(\s*(?:Request|request)\s*\(\s*""(?:cmd|command|shell|exec)""\s*\)\s*\)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                    new Regex(@"\bEval\s*\(\s*Request\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                },
                new[] { ".asp", ".aspx", ".ascx", ".ashx", ".asmx" },
                new[] {
                    "Remove the webshell file immediately.",
                    "Check IIS logs for command execution patterns.",
                    "Reset all service account credentials."
                }
            ),
            new YaraRule(
                "Webshell_JSP",
                "JSP webshell using Runtime.exec or ProcessBuilder",
                "Critical", 95,
                new[] {
                    new Regex(@"\bRuntime\.getRuntime\(\)\.exec\s*\(\s*request\.getParameter", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                    new Regex(@"\bnew\s+ProcessBuilder\s*\(.*request\.getParameter", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                },
                new[] { ".jsp", ".jspx" },
                new[] { "Remove the webshell file. Audit application server logs." }
            ),
            new YaraRule(
                "Webshell_Python",
                "Python webshell using os.system/subprocess/os.popen with request parameters",
                "Critical", 95,
                new[] {
                    new Regex(@"\bos\.(?:system|popen)\s*\(\s*request\.(?:args|form|values)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                    new Regex(@"\bsubprocess\.(?:call|Popen|check_output|run)\s*\(.*request\.(?:args|form|values)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                },
                new[] { ".py", ".pyc", ".wsgi" },
                new[] { "Remove the webshell file. Audit application logs." }
            ),

            // ─── Malware Indicators ───
            new YaraRule(
                "Malware_Suspicious_API",
                "Suspicious Windows API calls commonly used by malware (process injection, keylogging)",
                "High", 75,
                new[] {
                    new Regex(@"\b(?:VirtualAllocEx|WriteProcessMemory|CreateRemoteThread)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                    new Regex(@"\b(?:SetWindowsHookEx|GetAsyncKeyState|GetForegroundWindow)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                    new Regex(@"\b(?:OpenProcess|NtCreateThreadEx|QueueUserAPC)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                    new Regex(@"\b(?:URLDownloadToFile|WinHttpOpen|InternetOpenUrl)\b.*\bhttp", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                },
                new[] { ".exe", ".dll", ".sys", ".bin", ".ps1", ".vbs", ".bat", ".cmd", ".cs", ".cpp", ".c" },
                new[] {
                    "Analyze the binary in a sandbox environment.",
                    "Check for process injection or credential harvesting.",
                    "Submit to VirusTotal for further analysis."
                }
            ),
            new YaraRule(
                "Malware_PowerShell_Download",
                "PowerShell download cradle — common in malware droppers",
                "High", 80,
                new[] {
                    new Regex(@"IEX\s*\(\s*(?:New-Object\s+Net\.WebClient\)?\.DownloadString|Invoke-WebRequest|Invoke-RestMethod)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                    new Regex(@"Invoke-Expression\s*\(\s*(?:New-Object\s+Net\.WebClient\)?\.DownloadString|curl|wget)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                    new Regex(@"-?[eE](?:nc|ncod|ncoded[Cc]ommand)\s+[A-Za-z0-9+/=]{50,}", RegexOptions.Compiled),
                },
                new[] { ".ps1", ".psm1", ".bat", ".cmd", ".txt" },
                new[] {
                    "Check PowerShell transcript logs (if enabled).",
                    "Investigate the download URL for C2 infrastructure.",
                    "Scan the downloaded payload in a sandbox."
                }
            ),
            new YaraRule(
                "Malware_Reverse_Shell",
                "Reverse shell patterns — netcat, bash, Python, Perl, Ruby reverse shells",
                "Critical", 90,
                new[] {
                    // Bash reverse shell
                    new Regex(@"bash\s+-[ic]\s+.*>\s*&?\s*/dev/(?:tcp|udp)/", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                    // Netcat reverse shell
                    new Regex(@"\bnc\s+.*\s+-e\s+/bin/(?:bash|sh)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                    // Python reverse shell
                    new Regex(@"socket\.socket.*\.connect\s*\(.*os\.dup2.*/bin/(?:sh|bash)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                    // PHP reverse shell
                    new Regex(@"fsockopen\s*\(.*exec\s*\(.*/bin/(?:sh|bash)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                    // Perl reverse shell
                    new Regex(@"perl\s+-e\s+.*Socket.*connect.*exec.*/bin/(?:sh|bash)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                    // Ruby reverse shell
                    new Regex(@"ruby\s+-rsocket\s+-e.*TCPSocket.*exec.*/bin/(?:sh|bash)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                },
                new[] { ".sh", ".bash", ".py", ".pl", ".rb", ".php", ".txt", ".conf", ".cfg" },
                new[] {
                    "Check network connections for unauthorized outbound traffic.",
                    "Kill the reverse shell process immediately.",
                    "Audit system for persistence mechanisms (cron, systemd, rc.local)."
                }
            ),

            // ─── Sensitive Data Patterns ───
            new YaraRule(
                "Sensitive_CreditCard",
                "Credit card numbers in plaintext (PCI-DSS violation)",
                "High", 90,
                new[] {
                    // Visa, MasterCard, Amex, Discover, Diners
                    new Regex(@"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12}|3(?:0[0-5]|[68][0-9])[0-9]{11})\b", RegexOptions.Compiled),
                },
                new[] { ".txt", ".log", ".csv", ".json", ".xml", ".sql", ".dump", ".bak", ".conf", ".cfg", ".env", ".ini", ".yaml", ".yml", ".md", ".html" },
                new[] {
                    "Remove credit card data from plaintext files immediately.",
                    "Implement PCI-DSS compliant tokenization or encryption.",
                    "Audit all backups and logs for stored card data.",
                    "This is a PCI-DSS violation — report to compliance team."
                }
            ),
            new YaraRule(
                "Sensitive_SSN",
                "US Social Security Numbers in plaintext (PII exposure)",
                "High", 85,
                new[] {
                    new Regex(@"\b(?!000|666|9\d{2})([0-8]\d{2}|7([0-6]\d))(?:[-\s]?)(?!00)\d{2}(?:[-\s]?)(?!0000)\d{4}\b", RegexOptions.Compiled),
                },
                new[] { ".txt", ".log", ".csv", ".json", ".xml", ".sql", ".dump", ".bak", ".conf", ".cfg", ".env", ".ini", ".yaml", ".yml", ".md", ".html" },
                new[] {
                    "Remove SSNs from plaintext files.",
                    "Apply data masking or encryption for PII.",
                    "This may be a regulatory violation (GDPR, CCPA, HIPAA).",
                    "Report to Data Protection Officer."
                }
            ),
            new YaraRule(
                "Sensitive_API_Keys",
                "API keys and credentials in plaintext files",
                "High", 80,
                new[] {
                    new Regex(@"(?:api[_-]?key|apikey|secret[_-]?key|auth[_-]?token|access[_-]?token)\s*[:=]\s*['""]?['""]?([A-Za-z0-9_\-+/=]{20,})", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                    new Regex(@"\b(?:AKIA[0-9A-Z]{16})\b", RegexOptions.Compiled), // AWS Access Key
                    new Regex(@"\b(?:AIza[0-9A-Za-z\-_]{35})\b", RegexOptions.Compiled), // Google API Key
                    new Regex(@"\b(?:gh[pousr]_[A-Za-z0-9_]{36,})\b", RegexOptions.Compiled), // GitHub Token
                    new Regex(@"\b(?:sk-[A-Za-z0-9]{32,})\b", RegexOptions.Compiled), // Stripe/OpenAI API Key
                    new Regex(@"\b(?:xox[bpras]-[A-Za-z0-9\-]+)\b", RegexOptions.Compiled), // Slack Token
                    new Regex(@"\b(?:AC[a-f0-9]{32})\b", RegexOptions.Compiled), // Twilio Auth Token
                },
                new[] { ".txt", ".log", ".csv", ".json", ".xml", ".sql", ".dump", ".bak", ".conf", ".cfg", ".env", ".ini", ".yaml", ".yml", ".md", ".html", ".js", ".ts" },
                new[] {
                    "Remove API keys from files immediately and rotate them.",
                    "Store secrets in a vault (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault).",
                    "Use .gitignore to prevent committing secrets.",
                    "Check git history — secrets may have been committed previously."
                }
            ),
            new YaraRule(
                "Sensitive_Private_Keys",
                "Private keys (RSA, EC, DSA, OpenSSH) in plaintext",
                "Critical", 95,
                new[] {
                    new Regex(@"-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PGP)\s+PRIVATE\s+KEY-----", RegexOptions.Compiled),
                    new Regex(@"-----BEGIN\s+PRIVATE\s+KEY-----", RegexOptions.Compiled),
                    new Regex(@"-----BEGIN\s+ENCRYPTED\s+PRIVATE\s+KEY-----", RegexOptions.Compiled),
                },
                new[] { ".txt", ".log", ".pem", ".key", ".p12", ".pfx", ".crt", ".cer", ".der", ".csr", ".pub", ".cfg", ".conf", ".env", ".ini" },
                new[] {
                    "Private keys must NEVER be in plaintext accessible locations.",
                    "Move keys to a secure key store (KMS, HSM, or encrypted vault).",
                    "Rotate any exposed keys immediately.",
                    "Audit all systems that had access to this key."
                }
            ),

            // ─── Malware Persistence ───
            new YaraRule(
                "Malware_Persistence",
                "Malware persistence mechanisms (registry, cron, systemd, launchd)",
                "High", 80,
                new[] {
                    new Regex(@"\b(?:HKLM|HKCU|HKU)\\(?:SOFTWARE|SYSTEM)\\.*\\Run\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                    new Regex(@"schtasks\s+/create\s+.*/sc\s+(?:ONLOGON|ONSTART|DAILY|MINUTE)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                    new Regex(@"@reboot\s+.*(?:nc\s|bash\s+-[ic]|/tmp/|curl\s|wget\s)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                    new Regex(@"/etc/cron\.(?:daily|hourly|weekly|monthly)/[a-z0-9]+", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                },
                new[] { ".sh", ".bash", ".py", ".ps1", ".bat", ".cmd", ".vbs", ".txt", ".conf", ".cfg" },
                new[] {
                    "Remove unauthorized persistence mechanisms.",
                    "Check for related malware artifacts.",
                    "Monitor for recurrence after cleanup."
                }
            ),

            // ─── Obfuscation Indicators ───
            new YaraRule(
                "Malware_Obfuscation",
                "Code obfuscation patterns — base64-encoded payloads, XOR decoding, string obfuscation",
                "Medium", 65,
                new[] {
                    new Regex(@"FromBase64String\s*\(\s*""[A-Za-z0-9+/=]{200,}""", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                    new Regex(@"\b(?:eval|exec)\s*\(\s*(?:base64_decode|atob)\s*\(\s*""[A-Za-z0-9+/=]{100,}""", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                    new Regex(@"\b(?:XOR|xor)\s+.*\b(?:key|0x[0-9a-f]+)\b.*\bfor\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                },
                new[] { ".php", ".py", ".js", ".vbs", ".ps1", ".bat", ".cmd" },
                new[] {
                    "Decode and analyze obfuscated content.",
                    "Obfuscation alone is not malicious, but warrants investigation.",
                    "Submit to a malware analysis sandbox."
                }
            ),
        };
    }

    /// <summary>
    /// Initializes the YARA scanner and detects whether the yara CLI tool is available.
    /// </summary>
    public YaraScanner(ConfigManager config)
    {
        _config = config;
        _outputDir = config.OutputDirectory;
        _yaraCliAvailable = CheckYaraCli();

        if (_yaraCliAvailable)
        {
            Logger.Info("YARA CLI detected — will use real YARA scanning for rules.");
        }
        else
        {
            Logger.Info("YARA CLI not found — using embedded regex-based rules.");
        }
    }

    /// <summary>
    /// Scans the target directory (or file) using YARA regex rules.
    /// If the yara CLI is installed, shells out to it for real YARA scanning.
    /// </summary>
    /// <param name="target">Directory or file path to scan.</param>
    /// <returns>Scan results with matched rules and findings flagged by severity.</returns>
    public async Task<ScanResult> ScanAsync(string target)
    {
        var result = new ScanResult
        {
            ModuleName = "YARA Scanner",
            TargetUrl = target,
            StartTime = DateTime.UtcNow
        };

        try
        {
            List<string> files;

            if (Directory.Exists(target))
            {
                files = Directory.GetFiles(target, "*", SearchOption.AllDirectories).ToList();
                result.EndpointsTested = files.Count;
            }
            else if (File.Exists(target))
            {
                files = new List<string> { target };
                result.EndpointsTested = 1;
            }
            else
            {
                AddFinding(result, target, "", "YARA: Invalid Target",
                    $"Target '{target}' is not a valid file or directory.",
                    "Info", 10, null, "");
                result.Completed = true;
                result.EndTime = DateTime.UtcNow;
                return result;
            }

            // If yara CLI is available, write rules file and use it
            if (_yaraCliAvailable)
            {
                await ScanWithYaraCliAsync(result, files, target);
            }

            // Always run embedded regex rules (complementary to YARA CLI)
            await ScanWithEmbeddedRulesAsync(result, files);

            result.Completed = true;
            Logger.Info($"YARA scan complete: {files.Count} files, {result.Vulnerabilities.Count} findings");
        }
        catch (Exception ex)
        {
            result.ErrorMessage = ex.Message;
            Logger.Error($"YARA Scanner failed: {ex.Message}");
        }

        result.EndTime = DateTime.UtcNow;
        return result;
    }

    // ─── YARA CLI Integration ───

    /// <summary>Checks if the yara command-line tool is installed.</summary>
    private static bool CheckYaraCli()
    {
        try
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "yara",
                    Arguments = "--version",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };
            process.Start();
            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit(2000);

            if (process.ExitCode == 0)
            {
                Logger.Debug($"YARA CLI version: {output.Trim()}");
                return true;
            }
        }
        catch
        {
            // YARA not installed or not in PATH
        }

        try
        {
            // Check alternative names
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "yara64",
                    Arguments = "--version",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };
            process.Start();
            process.WaitForExit(2000);
            if (process.ExitCode == 0) return true;
        }
        catch
        {
            // Not found
        }

        return false;
    }

    /// <summary>Generates a temporary YARA rules file and shells out to yara CLI.</summary>
    private async Task ScanWithYaraCliAsync(ScanResult result, List<string> files, string target)
    {
        try
        {
            var rulesFile = Path.Combine(_outputDir, "seckit_rules.yar");
            var yaraRules = GenerateYaraRules();
            await File.WriteAllTextAsync(rulesFile, yaraRules);

            // Limit to 500 files to avoid performance issues
            var scanTargets = files.Count > 500 ? new List<string> { target } : files;

            foreach (var scanTarget in scanTargets.Take(1)) // yara handles recursive by default
            {
                using var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "yara",
                        Arguments = $"-r -s -w \"{rulesFile}\" \"{target}\"",
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                var stdout = await process.StandardOutput.ReadToEndAsync();
                var stderr = await process.StandardError.ReadToEndAsync();
                await process.WaitForExitAsync();

                if (!string.IsNullOrWhiteSpace(stderr))
                {
                    Logger.Debug($"YARA CLI stderr: {stderr.Trim()}");
                }

                if (process.ExitCode == 0 && !string.IsNullOrWhiteSpace(stdout))
                {
                    ParseYaraCliOutput(result, stdout);
                }

                break; // Only scan once — yara handles the directory recursively
            }

            // Cleanup
            try { File.Delete(rulesFile); } catch { }
        }
        catch (Exception ex)
        {
            Logger.Debug($"YARA CLI scanning failed: {ex.Message}");
        }
    }

    /// <summary>Parses YARA CLI output into vulnerability findings.</summary>
    private void ParseYaraCliOutput(ScanResult result, string stdout)
    {
        var lines = stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        string? currentRule = null;

        foreach (var line in lines)
        {
            // YARA output format: "rule_name file_path:offset:matched_string"
            // Or multiline: "rule_name" then "0xoffset:matched_string file_path"
            var match = Regex.Match(line, @"^(\w+)\s+(.+)$");
            if (match.Success)
            {
                currentRule = match.Groups[1].Value;
                var details = match.Groups[2].Value;
                var ruleDefinition = EmbeddedRules.FirstOrDefault(r => r.Name == currentRule);
                if (ruleDefinition != null && details.Contains(':'))
                {
                    var fileMatch = Regex.Match(details, @"^(.+):(0x[0-9a-f]+):(.+)$");
                    if (fileMatch.Success)
                    {
                        AddFinding(result, fileMatch.Groups[1].Value, "",
                            $"YARA (CLI): {ruleDefinition.Name}",
                            $"YARA rule '{ruleDefinition.Name}' matched: {ruleDefinition.Description}",
                            ruleDefinition.Severity, ruleDefinition.Confidence,
                            ruleDefinition.Remediation,
                            $"Offset: {fileMatch.Groups[2].Value}, Match: {fileMatch.Groups[3].Value[..Math.Min(fileMatch.Groups[3].Value.Length, 100)]}");
                    }
                }
            }
        }
    }

    // ─── Embedded Regex Scanning ───

    /// <summary>Scans files using embedded regex-based YARA rules.</summary>
    private async Task ScanWithEmbeddedRulesAsync(ScanResult result, List<string> files)
    {
        foreach (var file in files.Take(1000)) // Limit to 1000 files
        {
            try
            {
                var fileInfo = new FileInfo(file);

                // Skip very large files
                if (fileInfo.Length > 10 * 1024 * 1024) // 10MB
                {
                    Logger.Debug($"Skipping large file for YARA scan: {file} ({fileInfo.Length / 1024 / 1024}MB)");
                    continue;
                }

                // Skip binary files by extension (YARA handles this but regex doesn't)
                var ext = fileInfo.Extension.ToLowerInvariant();
                if (IsBinaryExtension(ext) && ext != ".exe" && ext != ".dll" && ext != ".bin")
                {
                    continue;
                }

                var content = await File.ReadAllTextAsync(file);

                // Apply each rule
                foreach (var rule in EmbeddedRules)
                {
                    // Check if this rule targets this file extension
                    if (rule.FileExtensions.Length > 0 &&
                        !rule.FileExtensions.Contains(ext))
                    {
                        continue;
                    }

                    foreach (var pattern in rule.Patterns)
                    {
                        var matches = pattern.Matches(content);
                        foreach (System.Text.RegularExpressions.Match match in matches)
                        {
                            result.RequestsSent++;

                            // Extract context
                            var offset = match.Index;
                            var lineNumber = content[..Math.Min(offset, content.Length)].Count(c => c == '\n') + 1;
                            var matchedString = match.Value.Length > 200
                                ? match.Value[..200] + "..."
                                : match.Value;

                            AddFinding(result, file, rule.Name,
                                $"YARA: {rule.Name}",
                                rule.Description,
                                rule.Severity, rule.Confidence,
                                rule.Remediation,
                                $"Line {lineNumber}, Offset {offset}, Match: {matchedString}");

                            // Only report first match per rule per file to avoid duplicates
                            goto nextRule;
                        }
                    }
                    nextRule:;
                }
            }
            catch (UnauthorizedAccessException)
            {
                Logger.Debug($"Access denied: {file}");
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                Logger.Debug($"Could not scan {file}: {ex.Message}");
            }
        }
    }

    // ─── YARA Rule File Generation ───

    /// <summary>Generates a YARA-compatible rules file string from embedded rules.</summary>
    private static string GenerateYaraRules()
    {
        var sb = new StringBuilder();
        sb.AppendLine("/* Auto-generated by SecKit YARA Scanner */");
        sb.AppendLine("/* https://github.com/VirusTotal/yara */");
        sb.AppendLine();

        foreach (var rule in EmbeddedRules)
        {
            // Only include rules where we can express them as YARA conditions
            // For complex regex rules, use the "strings" and "condition" syntax
            sb.AppendLine($"rule {rule.Name}");
            sb.AppendLine("{");
            sb.AppendLine("    meta:");
            sb.AppendLine($"        description = \"{rule.Description}\"");
            sb.AppendLine($"        severity = \"{rule.Severity}\"");
            sb.AppendLine($"        author = \"SecKit\"");
            sb.AppendLine("    strings:");

            for (int i = 0; i < rule.Patterns.Length; i++)
            {
                // Convert .NET regex to YARA-compatible regex
                var yaraRegex = ConvertToYaraRegex(rule.Patterns[i].ToString());
                sb.AppendLine($"        $r{i} = /{yaraRegex}/");
            }

            sb.Append("    condition:\n        any of them\n");
            sb.AppendLine("}");
            sb.AppendLine();
        }

        return sb.ToString();
    }

    /// <summary>Converts a .NET regex pattern to YARA regex syntax.</summary>
    private static string ConvertToYaraRegex(string dotnetPattern)
    {
        // YARA uses its own regex flavor — similar but with differences
        // Remove .NET-specific flags and constructs
        var pattern = dotnetPattern;

        // Remove .NET inline options like (?i), (?-i), (?s), (?m)
        pattern = Regex.Replace(pattern, @"\(\?[imnsx\-]+\)", "");

        // Convert \b (word boundary) — YARA doesn't support it directly
        // For YARA scanning, we use hex/string matching instead
        // For now, keep as-is — some YARA builds support \b

        return pattern;
    }

    // ─── Helpers ───

    /// <summary>Checks if a file extension typically indicates a binary file.</summary>
    private static bool IsBinaryExtension(string extension)
    {
        return extension switch
        {
            ".exe" or ".dll" or ".so" or ".dylib" or ".bin" or ".dat" or ".sys" or ".drv" => true,
            ".zip" or ".tar" or ".gz" or ".bz2" or ".7z" or ".rar" => true,
            ".jpg" or ".jpeg" or ".png" or ".gif" or ".bmp" or ".ico" or ".webp" => true,
            ".mp3" or ".mp4" or ".avi" or ".mov" or ".mkv" or ".wmv" or ".flv" => true,
            ".pdf" or ".doc" or ".docx" or ".xls" or ".xlsx" or ".ppt" or ".pptx" => true,
            ".ttf" or ".otf" or ".woff" or ".woff2" or ".eot" => true,
            _ => false
        };
    }

    private void AddFinding(ScanResult result, string file, string rule, string type,
        string description, string severity, int confidence, string[]? remediation, string evidence)
    {
        var vuln = new Vulnerability
        {
            Type = type,
            Severity = severity,
            Url = file,
            Parameter = "YARA",
            Payload = rule.Length > 0 ? rule : "regex-match",
            Description = description,
            Evidence = evidence.Length > 500 ? evidence[..500] + "..." : evidence,
            Remediation = remediation != null ? string.Join(" ", remediation) : "Investigate the matched content and determine if it's malicious or a false positive.",
            Module = "YaraScanner",
            Confidence = confidence
        };
        result.Vulnerabilities.Add(vuln);
        Logger.LogVulnerability(vuln);
    }
}
