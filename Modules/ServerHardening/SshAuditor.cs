using System.Diagnostics;
using SecKit.Core;
using SecKit.Models;

namespace SecKit.Modules.ServerHardening;

/// <summary>
/// Audits SSH server configuration for common hardening weaknesses:
/// root login, password auth, default port, empty passwords, weak ciphers,
/// and authorized_keys file permissions.
/// </summary>
public class SshAuditor
{
    private static readonly string[] WeakCiphers =
    {
        "arcfour", "arcfour128", "arcfour256", "blowfish-cbc",
        "cast128-cbc", "3des-cbc", "aes128-cbc", "aes192-cbc",
        "aes256-cbc", "rijndael-cbc@lysator.liu.se"
    };

    private static readonly string[] WeakMacs =
    {
        "hmac-md5", "hmac-md5-96", "hmac-sha1-96",
        "hmac-ripemd160", "umac-64@openssh.com"
    };

    private static readonly string[] WeakKex =
    {
        "diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
        "diffie-hellman-group-exchange-sha1"
    };

    /// <summary>
    /// Audits the SSH server configuration on the target system.
    /// </summary>
    /// <param name="target">Target hostname or IP (typically localhost for server-local scans).</param>
    /// <returns>ScanResult containing SSH audit findings.</returns>
    public async Task<ScanResult> ScanAsync(string target)
    {
        var result = new ScanResult
        {
            ModuleName = "SSH Auditor",
            TargetUrl = target,
            StartTime = DateTime.UtcNow
        };

        try
        {
            Logger.Info("Auditing SSH server configuration...");

            var config = await ReadSshdConfigAsync();
            if (config.Count == 0)
            {
                result.Completed = true;
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "SSH Configuration",
                    Severity = "Info",
                    Description = "Could not read /etc/ssh/sshd_config. SSH server may not be installed.",
                    Remediation = "Install and configure OpenSSH server, or verify the sshd_config path.",
                    Module = "SshAuditor",
                    Confidence = 100
                });
                Logger.Info("SSH audit complete: sshd_config not found.");
                result.EndTime = DateTime.UtcNow;
                return result;
            }

            // Check key SSH config directives
            AuditDirective(config, result, "PermitRootLogin", "no",
                "Root login is allowed over SSH",
                "Set 'PermitRootLogin no' in /etc/ssh/sshd_config to disable direct root login.",
                "High");

            AuditDirective(config, result, "PasswordAuthentication", "no",
                "Password authentication is enabled (prefer key-based auth)",
                "Set 'PasswordAuthentication no' and use SSH keys instead.",
                "Medium");

            AuditDirectivePresent(config, result, "PubkeyAuthentication", "no",
                "Public key authentication is disabled",
                "Set 'PubkeyAuthentication yes' to enable public key authentication.",
                "High");

            AuditDirective(config, result, "PermitEmptyPasswords", "no",
                "Empty passwords are permitted for SSH login",
                "Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config.",
                "Critical");

            AuditDirective(config, result, "X11Forwarding", "no",
                "X11 forwarding is enabled (potential information leak)",
                "Set 'X11Forwarding no' unless required for specific use cases.",
                "Low");

            // Check default SSH port
            var portValue = GetConfigValue(config, "Port");
            if (portValue is null || portValue == "22")
            {
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "SSH Default Port",
                    Severity = "Low",
                    Description = "SSH is running on the default port 22. Consider changing to a non-standard port to reduce automated attacks.",
                    Remediation = "Set 'Port <non-standard>' in /etc/ssh/sshd_config and restart sshd.",
                    Evidence = $"Port {portValue ?? "22"}",
                    Module = "SshAuditor",
                    Confidence = 80
                });
            }

            // Check Protocol version
            var protoValue = GetConfigValue(config, "Protocol");
            if (protoValue is not null && protoValue.Contains("1") && !protoValue.Contains("2"))
            {
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "SSH Protocol Version",
                    Severity = "Critical",
                    Description = "SSH Protocol 1 is enabled. Protocol 1 has known security vulnerabilities.",
                    Remediation = "Set 'Protocol 2' in /etc/ssh/sshd_config and disable Protocol 1.",
                    Evidence = $"Protocol {protoValue}",
                    Module = "SshAuditor",
                    Confidence = 95
                });
            }

            // Check MaxAuthTries
            var maxAuthValue = GetConfigValue(config, "MaxAuthTries");
            if (maxAuthValue is not null && int.TryParse(maxAuthValue, out var maxAuth) && maxAuth > 6)
            {
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "SSH MaxAuthTries",
                    Severity = "Low",
                    Description = $"MaxAuthTries is set to {maxAuth} (recommended ≤ 6). High values facilitate brute-force attacks.",
                    Remediation = "Set 'MaxAuthTries 6' or lower in /etc/ssh/sshd_config.",
                    Evidence = $"MaxAuthTries {maxAuthValue}",
                    Module = "SshAuditor",
                    Confidence = 70
                });
            }

            // Check weak ciphers
            var ciphers = GetConfigValues(config, "Ciphers");
            foreach (var weak in WeakCiphers)
            {
                if (ciphers.Any(c => c.Contains(weak, StringComparison.OrdinalIgnoreCase)))
                {
                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = "SSH Weak Cipher",
                        Severity = "High",
                        Description = $"Weak cipher '{weak}' is enabled in SSH configuration.",
                        Remediation = "Remove weak ciphers from the Ciphers directive in sshd_config. Use only AES-GCM or ChaCha20-Poly1305.",
                        Evidence = $"Cipher: {weak}",
                        Module = "SshAuditor",
                        Confidence = 85
                    });
                    break;
                }
            }

            // Check weak MACs
            var macs = GetConfigValues(config, "MACs");
            foreach (var weak in WeakMacs)
            {
                if (macs.Any(m => m.Contains(weak, StringComparison.OrdinalIgnoreCase)))
                {
                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = "SSH Weak MAC",
                        Severity = "Medium",
                        Description = $"Weak MAC algorithm '{weak}' is enabled in SSH configuration.",
                        Remediation = "Remove weak MACs from sshd_config. Use hmac-sha2-256 or hmac-sha2-512.",
                        Evidence = $"MAC: {weak}",
                        Module = "SshAuditor",
                        Confidence = 80
                    });
                    break;
                }
            }

            // Check weak Kex algorithms
            var kex = GetConfigValues(config, "KexAlgorithms");
            foreach (var weak in WeakKex)
            {
                if (kex.Any(k => k.Contains(weak, StringComparison.OrdinalIgnoreCase)))
                {
                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = "SSH Weak Kex",
                        Severity = "Medium",
                        Description = $"Weak key exchange algorithm '{weak}' is enabled in SSH configuration.",
                        Remediation = "Remove weak Kex algorithms from sshd_config. Use curve25519-sha256 or diffie-hellman-group-exchange-sha256.",
                        Evidence = $"Kex: {weak}",
                        Module = "SshAuditor",
                        Confidence = 80
                    });
                    break;
                }
            }

            // Check authorized_keys file permissions
            await AuditAuthorizedKeysAsync(result);

            result.Completed = true;
            Logger.Info($"SSH audit complete: {result.Vulnerabilities.Count} findings.");
        }
        catch (Exception ex)
        {
            result.ErrorMessage = ex.Message;
            Logger.Error($"SSH auditor failed: {ex.Message}");
        }

        result.EndTime = DateTime.UtcNow;
        return result;
    }

    /// <summary>Reads and parses /etc/ssh/sshd_config into a list of key-value pairs.</summary>
    private static async Task<Dictionary<string, List<string>>> ReadSshdConfigAsync()
    {
        var config = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        var output = await RunCommandAsync("cat /etc/ssh/sshd_config 2>/dev/null");

        if (string.IsNullOrWhiteSpace(output))
            return config;

        foreach (var line in output.Split('\n'))
        {
            var trimmed = line.Trim();
            if (string.IsNullOrWhiteSpace(trimmed) || trimmed.StartsWith('#'))
                continue;

            var parts = trimmed.Split(new[] { ' ', '\t' }, 2, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) continue;

            var key = parts[0];
            var value = parts[1].Split('#')[0].Trim();

            if (!config.ContainsKey(key))
                config[key] = new List<string>();
            config[key].Add(value);
        }

        return config;
    }

    /// <summary>Checks if a directive has a non-recommended value.</summary>
    private static void AuditDirective(
        Dictionary<string, List<string>> config, ScanResult result,
        string directive, string recommended, string description,
        string remediation, string severity)
    {
        var value = GetConfigValue(config, directive);
        if (value is not null && !value.Equals(recommended, StringComparison.OrdinalIgnoreCase))
        {
            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "SSH Configuration",
                Severity = severity,
                Description = description,
                Remediation = remediation,
                Evidence = $"{directive} {value}",
                Module = "SshAuditor",
                Confidence = 85
            });
        }
    }

    /// <summary>Checks if a directive is present with a specific disallowed value.</summary>
    private static void AuditDirectivePresent(
        Dictionary<string, List<string>> config, ScanResult result,
        string directive, string disallowedValue, string description,
        string remediation, string severity)
    {
        var value = GetConfigValue(config, directive);
        if (value is not null && value.Equals(disallowedValue, StringComparison.OrdinalIgnoreCase))
        {
            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "SSH Configuration",
                Severity = severity,
                Description = description,
                Remediation = remediation,
                Evidence = $"{directive} {value}",
                Module = "SshAuditor",
                Confidence = 85
            });
        }
    }

    /// <summary>Gets the first value for a configuration directive.</summary>
    private static string? GetConfigValue(Dictionary<string, List<string>> config, string key)
    {
        return config.TryGetValue(key, out var values) && values.Count > 0
            ? values[0]
            : null;
    }

    /// <summary>Gets all values for a configuration directive (for multi-value directives like Ciphers).</summary>
    private static List<string> GetConfigValues(Dictionary<string, List<string>> config, string key)
    {
        if (!config.TryGetValue(key, out var values) || values.Count == 0)
            return new List<string>();

        return values.SelectMany(v => v.Split(',', StringSplitOptions.RemoveEmptyEntries)
            .Select(s => s.Trim()))
            .ToList();
    }

    /// <summary>Checks authorized_keys files for weak permissions.</summary>
    private static async Task AuditAuthorizedKeysAsync(ScanResult result)
    {
        try
        {
            // Find all authorized_keys files
            var findOutput = await RunCommandAsync(
                "find /home /root -name authorized_keys -type f 2>/dev/null");

            if (string.IsNullOrWhiteSpace(findOutput))
                return;

            foreach (var file in findOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var trimmed = file.Trim();
                if (string.IsNullOrWhiteSpace(trimmed)) continue;

                // Check permissions
                var statOutput = await RunCommandAsync(
                    $"stat -c '%a %U %G' '{trimmed}' 2>/dev/null");

                if (string.IsNullOrWhiteSpace(statOutput)) continue;

                var parts = statOutput.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 3) continue;

                var perms = parts[0];
                var owner = parts[1];
                var group = parts[2];

                // Flag if world-readable or group-writable
                if (perms.Length == 3 && (perms[2] != '0' || perms[1] > '0'))
                {
                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = "SSH Authorized Keys Permissions",
                        Severity = "High",
                        Description = $"authorized_keys file at '{trimmed}' has weak permissions ({perms}). Owner: {owner}, Group: {group}.",
                        Remediation = $"Run: chmod 600 '{trimmed}' to restrict access to owner only.",
                        Evidence = $"File: {trimmed} | Perms: {perms} | Owner: {owner}:{group}",
                        Module = "SshAuditor",
                        Confidence = 90
                    });
                }

                // Flag if not owned by the expected user
                var expectedDir = Path.GetDirectoryName(trimmed);
                var expectedUser = expectedDir?.Split('/').LastOrDefault();
                if (!string.IsNullOrEmpty(expectedUser) && owner != expectedUser && owner != "root")
                {
                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = "SSH Authorized Keys Ownership",
                        Severity = "Medium",
                        Description = $"authorized_keys at '{trimmed}' is owned by '{owner}' instead of expected user.",
                        Remediation = $"Run: chown {expectedUser} '{trimmed}'",
                        Evidence = $"File: {trimmed} | Owner: {owner} (expected: {expectedUser})",
                        Module = "SshAuditor",
                        Confidence = 75
                    });
                }
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"Authorized keys audit failed: {ex.Message}");
        }
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
