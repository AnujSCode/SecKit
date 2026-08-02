using System.Text.RegularExpressions;
using SecKit.Core;
using SecKit.Models;

namespace SecKit.Modules.TrafficMonitor;

/// <summary>Pattern-matching engine for detecting common web attacks in HTTP traffic.</summary>
public class AttackDetector
{
    private readonly ConfigManager _config;

    private static readonly (string Name, string Pattern, string Category, string Severity)[] AttackPatterns =
    {
        // SQL Injection patterns
        ("SQLi - SELECT/UNION", @"(?i)(\bSELECT\b.*\bFROM\b|\bUNION\b.*\bSELECT\b)", "SQL Injection", "Critical"),
        ("SQLi - DROP/ALTER", @"(?i)\b(DROP\s+TABLE|ALTER\s+TABLE|TRUNCATE\s+TABLE)\b", "SQL Injection", "Critical"),
        ("SQLi - Comment bypass", @"(?i)(--\s|#\s*$|/\*.*\*/)", "SQL Injection", "Medium"),
        ("SQLi - Boolean", @"(?i)(\bOR\b\s+['""]?\d+['""]?\s*=\s*['""]?\d+['""]?|\b1\s*=\s*1\b)", "SQL Injection", "Critical"),
        ("SQLi - UNION injection", @"(?i)UNION\s+(ALL\s+)?SELECT\s+(NULL|@@version|database\(\))", "SQL Injection", "Critical"),
        ("SQLi - Time-based", @"(?i)(\bSLEEP\s*\(|WAITFOR\s+DELAY|pg_sleep|BENCHMARK\s*\()", "SQL Injection", "High"),
        ("SQLi - Error-based", @"(?i)(CONVERT\s*\(\s*int\s*,\s*@@version|extractvalue\s*\(|updatexml\s*\()", "SQL Injection", "High"),
        ("SQLi - Stacked queries", @"(?i);\s*(DROP|EXEC|EXECUTE|SHUTDOWN)\b", "SQL Injection", "Critical"),
        
        // XSS patterns
        ("XSS - Script tag", @"(?i)<\s*script[^>]*>.*?<\s*/\s*script\s*>", "XSS", "Critical"),
        ("XSS - Event handler", @"(?i)\bon\w+\s*=\s*[^>]*\b(alert|confirm|prompt|eval)\s*\(?", "XSS", "Critical"),
        ("XSS - JavaScript protocol", @"(?i)javascript\s*:", "XSS", "High"),
        ("XSS - IMG onerror", @"(?i)<img[^>]*\bonerror\s*=", "XSS", "Critical"),
        ("XSS - SVG onload", @"(?i)<svg[^>]*\bonload\s*=", "XSS", "Critical"),
        ("XSS - Iframe", @"(?i)<\s*iframe[^>]*>", "XSS", "Medium"),
        ("XSS - Encoded", @"(?i)%3Cscript%3E|&lt;script&gt;|\\x3cscript\\x3e", "XSS", "Critical"),
        ("XSS - Expression", @"(?i)expression\s*\([^)]*\balert\b", "XSS", "High"),
        
        // Path traversal
        ("Path Traversal - Unix", @"\.\./\.\./|\.\.\\\.\.\\", "Path Traversal", "Critical"),
        ("Path Traversal - Encoded", @"%2e%2e%2f|%2e%2e%5c|\.%00/", "Path Traversal", "Critical"),
        ("Path Traversal - etc/passwd", @"(?i)/etc/(passwd|shadow|hosts|group)", "Path Traversal", "Critical"),
        ("Path Traversal - Windows", @"(?i)(win\.ini|boot\.ini|system32\\drivers)", "Path Traversal", "Critical"),
        
        // Command injection
        ("Command Injection - Pipe", @"[;&|`]\s*(ls|cat|id|whoami|uname|pwd|dir|type|ipconfig|ifconfig)\b", "Command Injection", "Critical"),
        ("Command Injection - Dollar", @"\$\([a-zA-Z]", "Command Injection", "High"),
        ("Command Injection - Backtick", @"`[a-zA-Z]", "Command Injection", "Critical"),
        ("Command Injection - Shell", @"(?i)(\bexec\s*\(|\bsystem\s*\(|\bshell_exec\s*\(|\bpassthru\s*\()", "Command Injection", "Critical"),
        ("Command Injection - cURL/wget", @"(?i)(\bcurl\s+|wget\s+|nc\s+-|ncat\s+)", "Command Injection", "High"),
        
        // LFI/RFI
        ("LFI - PHP wrapper", @"(?i)php://(filter|input|data)", "LFI", "Critical"),
        ("LFI - expect wrapper", @"(?i)expect://", "LFI", "Critical"),
        ("RFI - Remote include", @"(?i)https?://[^/\s]+/[^?\s]*\.(php|txt)\?", "RFI", "Critical"),
        
        // SSRF
        ("SSRF - Internal IP", @"(?i)(127\.0\.0\.\d+|169\.254\.169\.254|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)", "SSRF", "High"),
        ("SSRF - Localhost", @"(?i)localhost(\b|:)", "SSRF", "Medium"),
        ("SSRF - File protocol", @"(?i)file:///", "SSRF", "Critical"),
        ("SSRF - Gopher protocol", @"(?i)gopher://", "SSRF", "Critical"),
        
        // XXE
        ("XXE - Entity", @"(?i)<!ENTITY\s+\w+\s+(SYSTEM|PUBLIC)", "XXE", "Critical"),
        ("XXE - DOCTYPE", @"(?i)<!DOCTYPE\s+\w+\s*\[", "XXE", "Critical"),
        
        // File upload
        ("File Upload - Web shell", @"(?i)\.(php\d*|phtml|asp|x?msp|aspx|jsp|cfm|cgi|pl|py|rb)\b", "File Upload", "Critical"),
        ("File Upload - Config", @"(?i)(\.htaccess|web\.config)", "File Upload", "Critical"),
        
        // Scanner/automation
        ("Scanner - User Agent", @"(?i)(nikto|nessus|nmap|sqlmap|acunetix|burp|w3af|dirbuster|gobuster|hydra|medusa|metasploit)", "Reconnaissance", "Medium"),
        ("Scanner - Headers", @"(?i)(X-Scanner:|X-Probe:|X-Forwarded-For:\s*127\.0\.0\.1)", "Reconnaissance", "Low"),
        
        // NoSQL injection
        ("NoSQLi - Operator injection", @"(?i)(\$ne\b|\$gt\b|\$lt\b|\$regex\b|\$where\b|\$exists\b)", "NoSQL Injection", "High"),
        ("NoSQLi - JSON injection", @"(?i)\{\s*""\$ne"":|""\$gt"":|""\$regex"":", "NoSQL Injection", "High"),
        
        // Template injection
        ("SSTI - Jinja2/Twig", @"(?i)\{\{.*?\}\}|\{%\s*.*?\s*%\}", "Template Injection", "Critical"),
        ("SSTI - FreeMarker", @"(?i)\$\{.*?}", "Template Injection", "Medium"),
        
        // LDAP injection
        ("LDAPi - Filters", @"(?i)(\(&|\(\||!\(|\)\()", "LDAP Injection", "Medium"),
        
        // Cookie manipulation
        ("Cookie - SQLi", @"(?i)Cookie:\s*.*?(--|' OR|\bUNION\b)", "Cookie Injection", "Critical"),
    };

    public AttackDetector(ConfigManager config)
    {
        _config = config;
    }

    /// <summary>Analyzes a single log line or request for attack patterns.</summary>
    public List<Vulnerability> AnalyzeLine(string input, string source = "unknown")
    {
        var findings = new List<Vulnerability>();

        foreach (var (name, pattern, category, severity) in AttackPatterns)
        {
            try
            {
                if (Regex.IsMatch(input, pattern, RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(100)))
                {
                    findings.Add(new Vulnerability
                    {
                        Type = $"Attack Detected: {name}",
                        Severity = severity,
                        Url = source,
                        Parameter = "request",
                        Payload = ExtractSuspiciousPart(input, pattern),
                        Description = $"Detected potential {category} attack pattern: {name}",
                        Remediation = GetRemediation(category),
                        Module = "AttackDetector",
                        Confidence = 80
                    });
                }
            }
            catch (RegexMatchTimeoutException)
            {
                Logger.Debug($"Regex timeout for pattern: {name}");
            }
        }

        return findings;
    }

    /// <summary>Analyzes a batch of log lines and returns aggregated results.</summary>
    public ScanResult AnalyzeBatch(IEnumerable<string> lines, string source = "batch")
    {
        var result = new ScanResult
        {
            ModuleName = "Attack Detector",
            TargetUrl = source,
            StartTime = DateTime.UtcNow
        };

        var lineList = lines.ToList();
        result.EndpointsTested = lineList.Count;

        foreach (var line in lineList)
        {
            result.RequestsSent++;
            var findings = AnalyzeLine(line, source);
            result.Vulnerabilities.AddRange(findings);
        }

        result.Completed = true;
        result.EndTime = DateTime.UtcNow;
        return result;
    }

    /// <summary>Analyzes a log file for attack patterns.</summary>
    public ScanResult AnalyzeFile(string logFilePath)
    {
        Logger.Info($"Analyzing log file: {logFilePath}");

        if (!File.Exists(logFilePath))
        {
            Logger.Error($"Log file not found: {logFilePath}");
            return new ScanResult
            {
                ModuleName = "Attack Detector",
                TargetUrl = logFilePath,
                StartTime = DateTime.UtcNow,
                EndTime = DateTime.UtcNow,
                ErrorMessage = "File not found"
            };
        }

        var lines = File.ReadLines(logFilePath);
        return AnalyzeBatch(lines, logFilePath);
    }

    private static string ExtractSuspiciousPart(string input, string pattern)
    {
        try
        {
            var match = Regex.Match(input, pattern, RegexOptions.IgnoreCase);
            if (match.Success)
            {
                var value = match.Value;
                return value.Length > 150 ? value[..150] + "..." : value;
            }
        }
        catch { }

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
