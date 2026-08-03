using System.Diagnostics;
using System.Text.Json;
using SecKit.Core;
using SecKit.Models;

namespace SecKit.Modules.ServerHardening;

/// <summary>
/// Audits Docker installations for security misconfigurations:
/// privileged containers, dangerous host mounts, exposed Docker socket,
/// insecure daemon config, excessive capabilities, and containers running as root.
/// Uses Docker CLI via Process.Start since Docker.DotNet may not be available.
/// </summary>
public class DockerAuditor
{
    // Capabilities that should raise flags when granted to containers
    private static readonly string[] DangerousCapabilities =
    {
        "CAP_SYS_ADMIN", "CAP_NET_ADMIN", "CAP_SYS_PTRACE",
        "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYSLOG",
        "CAP_NET_RAW", "CAP_DAC_READ_SEARCH", "CAP_SYS_BOOT",
        "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD",
        "CAP_AUDIT_CONTROL", "CAP_MAC_ADMIN", "CAP_MAC_OVERRIDE",
        "CAP_SYS_RESOURCE", "CAP_SYS_NICE"
    };

    // Sensitive host paths that should not be mounted into containers
    private static readonly string[] SensitiveMountPaths =
    {
        "/etc", "/root", "/var/run", "/proc", "/sys",
        "/home", "/var/log", "/boot"
    };

    /// <summary>
    /// Audits Docker security configuration on the target system.
    /// </summary>
    /// <param name="target">Target hostname or IP (typically localhost).</param>
    /// <returns>ScanResult with Docker audit findings.</returns>
    public async Task<ScanResult> ScanAsync(string target)
    {
        var result = new ScanResult
        {
            ModuleName = "Docker Auditor",
            TargetUrl = target,
            StartTime = DateTime.UtcNow
        };

        try
        {
            // Check if Docker is installed
            var dockerCheck = await RunCommandAsync("which docker 2>/dev/null");
            if (string.IsNullOrWhiteSpace(dockerCheck))
            {
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "Docker Status",
                    Severity = "Info",
                    Description = "Docker is not installed on this system.",
                    Remediation = "N/A — Docker not present.",
                    Module = "DockerAuditor",
                    Confidence = 100
                });
                result.Completed = true;
                result.EndTime = DateTime.UtcNow;
                return result;
            }

            Logger.Info("Auditing Docker security configuration...");

            var tasks = new[]
            {
                AuditDockerDaemonConfigAsync(result),
                AuditDockerContainersAsync(result),
                AuditDockerSocketAsync(result)
            };

            await Task.WhenAll(tasks);

            result.Completed = true;
            Logger.Info($"Docker audit complete: {result.Vulnerabilities.Count} findings.");
        }
        catch (Exception ex)
        {
            result.ErrorMessage = ex.Message;
            Logger.Error($"Docker auditor failed: {ex.Message}");
        }

        result.EndTime = DateTime.UtcNow;
        return result;
    }

    /// <summary>Audits Docker daemon configuration for security issues.</summary>
    private static async Task AuditDockerDaemonConfigAsync(ScanResult result)
    {
        try
        {
            // Check daemon.json
            var daemonConfig = await RunCommandAsync("cat /etc/docker/daemon.json 2>/dev/null");

            if (!string.IsNullOrWhiteSpace(daemonConfig))
            {
                try
                {
                    using var doc = JsonDocument.Parse(daemonConfig);
                    var root = doc.RootElement;

                    // Check for insecure registries
                    if (root.TryGetProperty("insecure-registries", out var registries) &&
                        registries.GetArrayLength() > 0)
                    {
                        var regList = string.Join(", ", registries.EnumerateArray().Select(r => r.GetString()));
                        result.Vulnerabilities.Add(new Vulnerability
                        {
                            Type = "Docker Insecure Registry",
                            Severity = "High",
                            Description = $"Insecure registries configured: {regList}. Docker will communicate with these registries over HTTP.",
                            Remediation = "Remove insecure registries from daemon.json or ensure they use HTTPS.",
                            Evidence = $"Registries: {regList}",
                            Module = "DockerAuditor",
                            Confidence = 85
                        });
                    }

                    // Check for userns-remap
                    if (root.TryGetProperty("userns-remap", out var usernsRemap))
                    {
                        var usernsValue = usernsRemap.GetString();
                        if (string.IsNullOrEmpty(usernsValue) || usernsValue == "false")
                        {
                            result.Vulnerabilities.Add(new Vulnerability
                            {
                                Type = "Docker User Namespace",
                                Severity = "Medium",
                                Description = "User namespace remapping is not enabled. Container root != host root without userns-remap.",
                                Remediation = "Enable userns-remap in daemon.json: {\"userns-remap\": \"default\"}",
                                Evidence = "userns-remap not enabled",
                                Module = "DockerAuditor",
                                Confidence = 80
                            });
                        }
                    }
                    else
                    {
                        // Not configured at all
                        result.Vulnerabilities.Add(new Vulnerability
                        {
                            Type = "Docker User Namespace",
                            Severity = "Medium",
                            Description = "User namespace remapping is not configured. Without it, container root maps to host root.",
                            Remediation = "Add 'userns-remap': 'default' to /etc/docker/daemon.json and restart Docker.",
                            Evidence = "userns-remap not configured",
                            Module = "DockerAuditor",
                            Confidence = 80
                        });
                    }

                    // Check for exposed TCP socket
                    if (root.TryGetProperty("hosts", out var hosts))
                    {
                        foreach (var host in hosts.EnumerateArray())
                        {
                            var hostStr = host.GetString();
                            if (hostStr is not null && (hostStr.Contains("tcp://") || hostStr.Contains("0.0.0.0")))
                            {
                                result.Vulnerabilities.Add(new Vulnerability
                                {
                                    Type = "Docker TCP Socket Exposed",
                                    Severity = "Critical",
                                    Description = $"Docker daemon is listening on TCP: {hostStr}. This allows remote Docker API access.",
                                    Remediation = "Remove TCP hosts from daemon.json. Use local Unix socket only.",
                                    Evidence = hostStr,
                                    Module = "DockerAuditor",
                                    Confidence = 95
                                });
                            }
                        }
                    }

                    // Check for live-restore disabling
                    if (root.TryGetProperty("live-restore", out var liveRestore) &&
                        !liveRestore.GetBoolean())
                    {
                        result.Vulnerabilities.Add(new Vulnerability
                        {
                            Type = "Docker Live Restore",
                            Severity = "Low",
                            Description = "Docker live-restore is disabled. Daemon restart will stop all containers.",
                            Remediation = "Enable live-restore in daemon.json for production systems.",
                            Evidence = "live-restore: false",
                            Module = "DockerAuditor",
                            Confidence = 60
                        });
                    }
                }
                catch (JsonException)
                {
                    Logger.Debug("Could not parse Docker daemon.json as valid JSON.");
                }
            }

            // Check Docker info for security-relevant settings
            var dockerInfo = await RunCommandAsync("docker info --format '{{json .}}' 2>/dev/null");
            if (!string.IsNullOrWhiteSpace(dockerInfo))
            {
                try
                {
                    using var doc = JsonDocument.Parse(dockerInfo);
                    var root = doc.RootElement;

                    // Check for deprecated/disabled security features
                    if (root.TryGetProperty("SecurityOptions", out var secOpts))
                    {
                        var secOptsList = secOpts.EnumerateArray()
                            .Select(o => o.GetString())
                            .ToList();

                        if (!secOptsList.Any(s => s is not null && s.Contains("seccomp")))
                        {
                            result.Vulnerabilities.Add(new Vulnerability
                            {
                                Type = "Docker Seccomp",
                                Severity = "Medium",
                                Description = "Seccomp profiles are not enabled for Docker. Containers have broader system call access.",
                                Remediation = "Enable seccomp profiles in Docker daemon configuration.",
                                Evidence = "seccomp not in SecurityOptions",
                                Module = "DockerAuditor",
                                Confidence = 75
                            });
                        }

                        if (!secOptsList.Any(s => s is not null && s.Contains("apparmor")))
                        {
                            Logger.Debug("AppArmor not in Docker security options (may not be available on this distro).");
                        }
                    }
                }
                catch (JsonException)
                {
                    Logger.Debug("Could not parse docker info output as JSON.");
                }
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"Docker daemon config audit failed: {ex.Message}");
        }
    }

    /// <summary>Audits running and stopped Docker containers for security issues.</summary>
    private static async Task AuditDockerContainersAsync(ScanResult result)
    {
        try
        {
            // Get list of all containers with IDs
            var containerIds = await RunCommandAsync("docker ps -aq 2>/dev/null");

            if (string.IsNullOrWhiteSpace(containerIds))
            {
                Logger.Debug("No Docker containers found (or docker ps failed).");
                return;
            }

            var ids = containerIds.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            var containerCount = ids.Length;

            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "Docker Containers Summary",
                Severity = "Info",
                Description = $"Found {containerCount} Docker containers (running + stopped).",
                Remediation = "Remove unused containers: docker container prune.",
                Evidence = $"Count: {containerCount}",
                Module = "DockerAuditor",
                Confidence = 100
            });

            // Inspect each container (limit to avoid timeout)
            var inspectLimit = Math.Min(containerCount, 20);
            for (int i = 0; i < inspectLimit; i++)
            {
                var containerId = ids[i].Trim();
                if (string.IsNullOrWhiteSpace(containerId)) continue;

                var inspectOutput = await RunCommandAsync(
                    $"docker inspect '{containerId}' 2>/dev/null");

                if (string.IsNullOrWhiteSpace(inspectOutput)) continue;

                try
                {
                    using var docs = JsonDocument.Parse(inspectOutput);
                    var container = docs.RootElement[0];

                    var name = container.GetProperty("Name").GetString() ?? containerId[..12];
                    var state = container.GetProperty("State");
                    var hostConfig = container.GetProperty("HostConfig");

                    // Check for privileged mode
                    if (hostConfig.TryGetProperty("Privileged", out var privileged) &&
                        privileged.GetBoolean())
                    {
                        result.Vulnerabilities.Add(new Vulnerability
                        {
                            Type = "Docker Privileged Container",
                            Severity = "Critical",
                            Description = $"Container '{name}' is running in privileged mode. It has full access to all host devices and kernel capabilities.",
                            Remediation = "Remove --privileged flag. Grant only required capabilities and device access.",
                            Evidence = $"Container: {name} | ID: {containerId[..12]}",
                            Module = "DockerAuditor",
                            Confidence = 95
                        });
                    }

                    // Check for host network mode
                    if (hostConfig.TryGetProperty("NetworkMode", out var netMode))
                    {
                        var netModeStr = netMode.GetString();
                        if (netModeStr == "host")
                        {
                            result.Vulnerabilities.Add(new Vulnerability
                            {
                                Type = "Docker Host Network Mode",
                                Severity = "High",
                                Description = $"Container '{name}' uses host network mode. It shares the host's network namespace and can bind to any port.",
                                Remediation = "Use bridge network mode and explicitly publish only required ports.",
                                Evidence = $"Container: {name} | NetworkMode: host",
                                Module = "DockerAuditor",
                                Confidence = 85
                            });
                        }
                    }

                    // Check for host PID namespace
                    if (hostConfig.TryGetProperty("PidMode", out var pidMode))
                    {
                        var pidModeStr = pidMode.GetString();
                        if (pidModeStr == "host")
                        {
                            result.Vulnerabilities.Add(new Vulnerability
                            {
                                Type = "Docker Host PID Namespace",
                                Severity = "High",
                                Description = $"Container '{name}' shares the host's PID namespace. It can see and potentially interact with host processes.",
                                Remediation = "Remove --pid=host flag unless absolutely required.",
                                Evidence = $"Container: {name} | PidMode: host",
                                Module = "DockerAuditor",
                                Confidence = 85
                            });
                        }
                    }

                    // Check for Docker socket mount
                    if (hostConfig.TryGetProperty("Binds", out var binds))
                    {
                        foreach (var bind in binds.EnumerateArray())
                        {
                            var bindStr = bind.GetString() ?? "";
                            if (bindStr.Contains("/var/run/docker.sock", StringComparison.OrdinalIgnoreCase))
                            {
                                result.Vulnerabilities.Add(new Vulnerability
                                {
                                    Type = "Docker Socket Mounted",
                                    Severity = "Critical",
                                    Description = $"Container '{name}' mounts the Docker socket. This gives the container full control over the Docker daemon and effectively root access to the host.",
                                    Remediation = "Remove the Docker socket mount. Use the Docker API or a dedicated sidecar container instead.",
                                    Evidence = $"Container: {name} | Mount: {bindStr}",
                                    Module = "DockerAuditor",
                                    Confidence = 95
                                });
                            }

                            // Check for sensitive host path mounts
                            foreach (var sensitive in SensitiveMountPaths)
                            {
                                if (bindStr.StartsWith(sensitive + ":", StringComparison.OrdinalIgnoreCase) ||
                                    bindStr.StartsWith(sensitive + "/", StringComparison.OrdinalIgnoreCase))
                                {
                                    result.Vulnerabilities.Add(new Vulnerability
                                    {
                                        Type = "Docker Sensitive Mount",
                                        Severity = "High",
                                        Description = $"Container '{name}' mounts a sensitive host path: {bindStr}.",
                                        Remediation = "Mount only specific required files/directories, not entire sensitive host directories.",
                                        Evidence = $"Container: {name} | Mount: {bindStr}",
                                        Module = "DockerAuditor",
                                        Confidence = 80
                                    });
                                }
                            }
                        }
                    }

                    // Check capabilities
                    if (hostConfig.TryGetProperty("CapAdd", out var capAdd))
                    {
                        foreach (var cap in capAdd.EnumerateArray())
                        {
                            var capStr = cap.GetString() ?? "";
                            if (DangerousCapabilities.Contains(capStr, StringComparer.OrdinalIgnoreCase))
                            {
                                result.Vulnerabilities.Add(new Vulnerability
                                {
                                    Type = "Docker Dangerous Capability",
                                    Severity = "High",
                                    Description = $"Container '{name}' has dangerous capability '{capStr}' added.",
                                    Remediation = $"Remove --cap-add={capStr}. Only add capabilities that are strictly required.",
                                    Evidence = $"Container: {name} | Capability: {capStr}",
                                    Module = "DockerAuditor",
                                    Confidence = 80
                                });
                            }
                        }
                    }

                    // Check if container is running as root
                    var config = container.GetProperty("Config");
                    if (config.TryGetProperty("User", out var userProp))
                    {
                        var user = userProp.GetString();
                        if (string.IsNullOrEmpty(user) || user == "root" || user == "0" || user == "0:0")
                        {
                            result.Vulnerabilities.Add(new Vulnerability
                            {
                                Type = "Docker Container Running as Root",
                                Severity = "Medium",
                                Description = $"Container '{name}' is running as root inside the container.",
                                Remediation = "Specify a non-root USER in your Dockerfile or use --user flag at runtime.",
                                Evidence = $"Container: {name} | User: {user ?? "root (default)"}",
                                Module = "DockerAuditor",
                                Confidence = 80
                            });
                        }
                    }
                    else
                    {
                        // No User specified = runs as root by default
                        result.Vulnerabilities.Add(new Vulnerability
                        {
                            Type = "Docker Container Running as Root",
                            Severity = "Medium",
                            Description = $"Container '{name}' has no USER specified (defaults to root inside the container).",
                            Remediation = "Specify a non-root USER in your Dockerfile.",
                            Evidence = $"Container: {name} | User: (default root)",
                            Module = "DockerAuditor",
                            Confidence = 80
                        });
                    }
                }
                catch (JsonException)
                {
                    Logger.Debug($"Could not parse docker inspect output for container {containerId[..12]}.");
                }
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"Docker container audit failed: {ex.Message}");
        }
    }

    /// <summary>Checks Docker socket permissions and ownership.</summary>
    private static async Task AuditDockerSocketAsync(ScanResult result)
    {
        try
        {
            // Check Docker socket permissions
            var socketStat = await RunCommandAsync("stat -c '%a %U %G' /var/run/docker.sock 2>/dev/null");

            if (!string.IsNullOrWhiteSpace(socketStat))
            {
                var parts = socketStat.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 3)
                {
                    var perms = parts[0];
                    var owner = parts[1];
                    var group = parts[2];

                    // Check if socket is world-readable/writable
                    if (perms.Length >= 3 && perms[perms.Length - 3] >= '6')
                    {
                        result.Vulnerabilities.Add(new Vulnerability
                        {
                            Type = "Docker Socket Permissions",
                            Severity = "High",
                            Description = $"Docker socket has overly permissive permissions ({perms}). Any user in the '{group}' group can control Docker.",
                            Remediation = "Restrict Docker socket access: chmod 660 /var/run/docker.sock. Use 'docker' group membership for authorized users.",
                            Evidence = $"Perms: {perms} | Owner: {owner}:{group}",
                            Module = "DockerAuditor",
                            Confidence = 85
                        });
                    }

                    // Docker group membership is effectively root
                    var groupMembers = await RunCommandAsync($"getent group '{group}' 2>/dev/null | cut -d: -f4");
                    if (!string.IsNullOrWhiteSpace(groupMembers) && group != "root")
                    {
                        var members = groupMembers.Trim().Split(',', StringSplitOptions.RemoveEmptyEntries);
                        if (members.Length > 0)
                        {
                            result.Vulnerabilities.Add(new Vulnerability
                            {
                                Type = "Docker Group Members",
                                Severity = "Medium",
                                Description = $"Users with Docker group access (effectively root): {groupMembers.Trim()}. Docker group membership bypasses all permission controls.",
                                Remediation = "Review who needs Docker access. Consider using Podman (rootless) or restricting sudo access instead.",
                                Evidence = $"Group: {group} | Members: {groupMembers.Trim()}",
                                Module = "DockerAuditor",
                                Confidence = 75
                            });
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"Docker socket audit failed: {ex.Message}");
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
