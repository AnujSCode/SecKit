using System.Text.RegularExpressions;
using SecKit.Core;
using SecKit.Models;

namespace SecKit.Modules.TrafficMonitor;

/// <summary>Pattern-matching engine for detecting common web attacks in HTTP traffic.</summary>
public class AttackDetector
{
    private readonly ConfigManager _config;
    private readonly (string Name, string Pattern, string Category, string Severity)[] _attackPatterns;

    public AttackDetector(ConfigManager config)
    {
        _config = config;
        _attackPatterns = config.AttackPatterns
            .Select(p => (p.Name, p.Pattern, p.Category, p.Severity)).ToArray();
    }

    public List<Vulnerability> AnalyzeLine(string input, string source = "unknown")
    {
        var findings = new List<Vulnerability>();
        foreach (var (name, pattern, category, severity) in _attackPatterns)
        {
            try
            {
                if (Regex.IsMatch(input, pattern, RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(100)))
                {
                    findings.Add(new Vulnerability
                    {
                        Type = $"Attack Detected: {name}", Severity = severity, Url = source,
                        Parameter = "request", Payload = ExtractSuspiciousPart(input, pattern),
                        Description = $"Detected potential {category} attack pattern: {name}",
                        Remediation = GetRemediation(category), Module = "AttackDetector", Confidence = 80
                    });
                }
            }
            catch (RegexMatchTimeoutException) { Logger.Debug($"Regex timeout for pattern: {name}"); }
        }
        return findings;
    }

    public ScanResult AnalyzeBatch(IEnumerable<string> lines, string source = "batch")
    {
        var result = new ScanResult { ModuleName = "Attack Detector", TargetUrl = source, StartTime = DateTime.UtcNow };
        var lineList = lines.ToList();
        result.EndpointsTested = lineList.Count;
        foreach (var line in lineList) { result.RequestsSent++; result.Vulnerabilities.AddRange(AnalyzeLine(line, source)); }
        result.Completed = true; result.EndTime = DateTime.UtcNow;
        return result;
    }

    public ScanResult AnalyzeFile(string logFilePath)
    {
        Logger.Info($"Analyzing log file: {logFilePath}");
        if (!File.Exists(logFilePath))
        {
            Logger.Error($"Log file not found: {logFilePath}");
            return new ScanResult { ModuleName = "Attack Detector", TargetUrl = logFilePath, StartTime = DateTime.UtcNow, EndTime = DateTime.UtcNow, ErrorMessage = "File not found" };
        }
        var lines = File.ReadLines(logFilePath);
        return AnalyzeBatch(lines, logFilePath);
    }

    private static string ExtractSuspiciousPart(string input, string pattern)
    {
        try { var match = Regex.Match(input, pattern, RegexOptions.IgnoreCase); if (match.Success) { var value = match.Value; return value.Length > 150 ? value[..150] + "..." : value; } } catch { }
        return input.Length > 150 ? input[..150] + "..." : input;
    }

    private static string GetRemediation(string category) => category switch
    {
        "SQL Injection" => "Use parameterized queries/prepared statements. Validate input. Use ORM.",
        "XSS" => "Encode output based on context. Implement Content Security Policy. Validate input.",
        "Path Traversal" => "Validate file paths. Use canonical paths. Avoid user input in file system calls.",
        "Command Injection" => "Avoid executing OS commands with user input. Use safe APIs. Validate and sanitize.",
        "LFI" or "RFI" => "Disable allow_url_include. Use static file includes. Validate paths.",
        "SSRF" => "Implement URL allowlists. Block internal IPs. Restrict protocols to http/https.",
        "XXE" => "Disable external entity processing in XML parsers.",
        "File Upload" => "Validate file types. Store outside web root. Scan for malware.",
        "Template Injection" => "Use sandboxed template engines. Never pass user input to templates.",
        "NoSQL Injection" => "Validate and sanitize NoSQL queries. Use typed query builders.",
        _ => "Implement defense-in-depth. Use WAF. Monitor and alert on suspicious activity."
    };
}
