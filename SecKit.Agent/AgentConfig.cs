namespace SecKit.Agent;

/// <summary>Configuration for the SecKit background agent.</summary>
public class AgentConfig
{
    /// <summary>Interval between scan cycles (default: 24 hours).</summary>
    public string ScanInterval { get; set; } = "24:00:00";

    /// <summary>Targets to monitor in agent mode.</summary>
    public List<string> MonitoredTargets { get; set; } = new();

    /// <summary>Scan types to run (vuln, network, ai, map, full).</summary>
    public string ScanType { get; set; } = "network";

    /// <summary>Scan profile (light, medium, deep).</summary>
    public string ScanProfile { get; set; } = "medium";

    /// <summary>Alert threshold: minimum vulnerability severity to trigger notification.</summary>
    public string AlertThreshold { get; set; } = "High";

    /// <summary>Telegram bot token for alerts.</summary>
    public string TelegramBotToken { get; set; } = "";

    /// <summary>Telegram chat ID for alerts.</summary>
    public string TelegramChatId { get; set; } = "";

    /// <summary>Enable webhook notifications.</summary>
    public bool WebhookEnabled { get; set; }

    /// <summary>Webhook URL for generic notifications.</summary>
    public string WebhookUrl { get; set; } = "";

    /// <summary>Path to appsettings.json for SecKit modules.</summary>
    public string ConfigPath { get; set; } = "appsettings.json";

    /// <summary>Log file path.</summary>
    public string LogPath { get; set; } = "logs/agent.log";

    /// <summary>Whether to monitor for new open ports (port diff).</summary>
    public bool MonitorOpenPorts { get; set; } = true;

    /// <summary>Whether to monitor log files for attacks.</summary>
    public bool MonitorLogs { get; set; } = false;

    /// <summary>Log files to monitor (if MonitorLogs is enabled).</summary>
    public List<string> LogFilesToMonitor { get; set; } = new() { "/var/log/apache2/access.log", "/var/log/nginx/access.log" };

    /// <summary>Parses the ScanInterval into a TimeSpan.</summary>
    public TimeSpan Interval
    {
        get
        {
            if (TimeSpan.TryParse(ScanInterval, out var ts))
                return ts;
            return TimeSpan.FromHours(24);
        }
    }
}
