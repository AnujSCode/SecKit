using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using SecKit.Core;

namespace SecKit.Modules.TrafficMonitor;

/// <summary>Real-time log file monitor with format detection and color-coded output (tail -f style).</summary>
public class LiveMonitor
{
    private readonly ConfigManager _config;
    private readonly CancellationTokenSource _cts = new();
    private readonly ConcurrentQueue<string> _recentLines = new();
    private long _totalLines;
    private long _errorLines;

    // Common log format patterns
    private static readonly Dictionary<string, Regex> LogFormats = new()
    {
        ["Apache Combined"] = new Regex(@"^(\S+) \S+ \S+ \[([^\]]+)\] ""(\S+) (\S+) \S+"" (\d{3}) (\S+) ""([^""]*)"" ""([^""]*)""$"),
        ["Apache Common"] = new Regex(@"^(\S+) \S+ \S+ \[([^\]]+)\] ""(\S+) (\S+) \S+"" (\d{3}) (\S+)$"),
        ["Nginx"] = new Regex(@"^(\S+) - \S+ \[([^\]]+)\] ""(\S+) (\S+) \S+"" (\d{3}) (\S+) ""([^""]*)"" ""([^""]*)""$"),
        ["IIS"] = new Regex(@"^(\S+) (\S+) (\S+) \[([^\]]+)\] ""(\S+) (\S+) \S+"" (\d{3}) \S+ \S+ \d+ \d+$"),
        ["JSON"] = new Regex(@"^\s*\{.*\}$"),
    };

    public LiveMonitor(ConfigManager config)
    {
        _config = config;
    }

    /// <summary>Monitors a log file in real-time with color-coded output.</summary>
    public async Task MonitorAsync(string logFilePath, CancellationToken externalCt = default)
    {
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token, externalCt);

        if (!File.Exists(logFilePath))
        {
            Logger.Error($"Log file not found: {logFilePath}");
            return;
        }

        Logger.Info($"Monitoring {logFilePath} (press Ctrl+C to stop)...");
        Logger.WriteLine("─".PadRight(60, '─'), ConsoleColor.Gray);

        // Detect format
        var format = DetectFormat(logFilePath);
        Logger.Info($"Detected log format: {format}");

        // Start monitoring
        var monitorTask = Task.Run(async () =>
        {
            try
            {
                using var fs = new FileStream(logFilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var reader = new StreamReader(fs);

                // Go to end of file (tail -f behavior)
                fs.Seek(0, SeekOrigin.End);

                while (!linkedCts.Token.IsCancellationRequested)
                {
                    var line = await reader.ReadLineAsync(linkedCts.Token);
                    if (line != null)
                    {
                        ProcessLine(line);
                    }
                    else
                    {
                        await Task.Delay(100, linkedCts.Token);
                    }
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                Logger.Error($"Monitor error: {ex.Message}");
            }
        }, linkedCts.Token);

        // Status display thread
        var statusTask = Task.Run(async () =>
        {
            while (!linkedCts.Token.IsCancellationRequested)
            {
                await Task.Delay(10000, linkedCts.Token);
                Logger.Info($"Monitor stats: {_totalLines} lines, {_errorLines} errors, {_recentLines.Count} queued");
            }
        }, linkedCts.Token);

        try
        {
            await monitorTask;
        }
        catch (OperationCanceledException) { }
    }

    /// <summary>Starts monitoring in background and returns control.</summary>
    public CancellationTokenSource StartBackground(string logFilePath)
    {
        _ = MonitorAsync(logFilePath, _cts.Token);
        return _cts;
    }

    /// <summary>Stops monitoring.</summary>
    public void Stop()
    {
        _cts.Cancel();
        Logger.Info($"Monitor stopped. Total: {_totalLines} lines, {_errorLines} errors");
    }

    private void ProcessLine(string line)
    {
        Interlocked.Increment(ref _totalLines);
        _recentLines.Enqueue(line);

        // Keep recent lines limited
        while (_recentLines.Count > 1000)
            _recentLines.TryDequeue(out _);

        // Parse status code
        int? statusCode = ExtractStatusCode(line);

        // Color-code by status
        var color = statusCode switch
        {
            >= 500 => ConsoleColor.Red,
            >= 400 => ConsoleColor.Yellow,
            >= 300 => ConsoleColor.Cyan,
            >= 200 => ConsoleColor.Green,
            _ => ConsoleColor.Gray
        };

        if (statusCode >= 400)
            Interlocked.Increment(ref _errorLines);

        // Truncate long lines for display
        var display = line.Length > 200 ? line[..200] + "..." : line;

        lock (this)
        {
            Logger.WriteLine($"  {DateTime.Now:HH:mm:ss} {display}", color);
        }
    }

    private static int? ExtractStatusCode(string line)
    {
        // Try common log format patterns
        foreach (var (_, regex) in LogFormats)
        {
            var match = regex.Match(line);
            if (match.Success)
            {
                // Status code is typically in group 5 (varies by format)
                for (int i = match.Groups.Count - 1; i > 0; i--)
                {
                    if (int.TryParse(match.Groups[i].Value, out var code) && code >= 100 && code < 600)
                        return code;
                }
            }
        }

        // Fallback: find any 3-digit number in the 100-599 range
        var m = Regex.Match(line, @"\b([1-5]\d{2})\b");
        if (m.Success && int.TryParse(m.Groups[1].Value, out var fallbackCode))
            return fallbackCode;

        return null;
    }

    private static string DetectFormat(string logFilePath)
    {
        try
        {
            var lines = File.ReadLines(logFilePath).Take(5).ToList();
            if (lines.Count == 0) return "Unknown";

            foreach (var line in lines)
            {
                foreach (var (name, regex) in LogFormats)
                {
                    if (regex.IsMatch(line)) return name;
                }
            }

            // Check if it's a custom format
            var firstLine = lines[0];
            if (firstLine.StartsWith("{")) return "JSON Lines";
            if (firstLine.Contains(" - - ")) return "Apache-like";
            if (firstLine.Contains(" | ")) return "Pipe-delimited";
        }
        catch { }

        return "Unknown";
    }

    /// <summary>Gets current monitoring statistics.</summary>
    public (long Total, long Errors, int Recent) GetStats() =>
        (_totalLines, _errorLines, _recentLines.Count);
}
