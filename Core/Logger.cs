using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecKit.Models;

namespace SecKit.Core;

/// <summary>Log levels for the SecKit logger.</summary>
public enum LogLevel
{
    Debug,
    Info,
    Warning,
    Error,
    Critical
}

/// <summary>Simple file-and-console logger with colored output and log levels.</summary>
public static class Logger
{
    private static readonly object _lock = new();
    private static string _logFilePath = "seckit.log";
    private static bool _initialized;

    /// <summary>Initializes the logger with an output file path.</summary>
    public static void Initialize(string logFilePath)
    {
        _logFilePath = logFilePath;
        var dir = Path.GetDirectoryName(logFilePath);
        if (!string.IsNullOrWhiteSpace(dir) && !Directory.Exists(dir))
            Directory.CreateDirectory(dir);
        _initialized = true;
    }

    /// <summary>Logs a message at the specified level.</summary>
    public static void Log(LogLevel level, string message)
    {
        var timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
        var levelStr = level.ToString().ToUpper().PadRight(8);
        var entry = $"[{timestamp}] [{levelStr}] {message}";

        lock (_lock)
        {
            // Console output with color
            var originalColor = Console.ForegroundColor;
            Console.ForegroundColor = level switch
            {
                LogLevel.Debug => ConsoleColor.Gray,
                LogLevel.Info => ConsoleColor.White,
                LogLevel.Warning => ConsoleColor.Yellow,
                LogLevel.Error => ConsoleColor.Red,
                LogLevel.Critical => ConsoleColor.DarkRed,
                _ => ConsoleColor.White
            };
            Console.WriteLine(entry);
            Console.ForegroundColor = originalColor;

            // File output
            try
            {
                if (_initialized)
                    File.AppendAllText(_logFilePath, entry + Environment.NewLine);
            }
            catch { /* silently fail file logging */ }
        }
    }

    public static void Debug(string message) => Log(LogLevel.Debug, message);
    public static void Info(string message) => Log(LogLevel.Info, message);
    public static void Warning(string message) => Log(LogLevel.Warning, message);
    public static void Error(string message) => Log(LogLevel.Error, message);
    public static void Critical(string message) => Log(LogLevel.Critical, message);

    /// <summary>Logs a vulnerability finding.</summary>
    public static void LogVulnerability(Vulnerability vuln)
    {
        var color = vuln.Severity switch
        {
            "Critical" => ConsoleColor.DarkRed,
            "High" => ConsoleColor.Red,
            "Medium" => ConsoleColor.Yellow,
            "Low" => ConsoleColor.DarkYellow,
            _ => ConsoleColor.Cyan
        };
        var old = Console.ForegroundColor;
        Console.ForegroundColor = color;
        Console.WriteLine($"  [{vuln.Severity.ToUpper()}] {vuln.Type} - {vuln.Url} ({vuln.Parameter})");
        Console.ForegroundColor = old;
        Log(LogLevel.Info, $"VULN [{vuln.Severity}] {vuln.Type}: {vuln.Description}");
    }

    /// <summary>Writes a line with the specified foreground color.</summary>
    public static void WriteLine(string message, ConsoleColor color)
    {
        var old = Console.ForegroundColor;
        Console.ForegroundColor = color;
        Console.WriteLine(message);
        Console.ForegroundColor = old;
    }
}
