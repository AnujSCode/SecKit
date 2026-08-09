using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecKit.Models;

namespace SecKit.Core;

/// <summary>Generates HTML and JSON security reports from scan results.</summary>
public static class ReportGenerator
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    /// <summary>
    /// Regenerates HTML reports from existing JSON report files in a directory.
    /// Useful after changing report templates or configuration without re-scanning.
    /// </summary>
    /// <param name="reportDir">Directory containing SecKit JSON report files.</param>
    /// <returns>Number of reports regenerated.</returns>
    public static int Regenerate(string reportDir)
    {
        if (!Directory.Exists(reportDir))
        {
            Logger.Error($"Report directory not found: {reportDir}");
            return 0;
        }

        var jsonFiles = Directory.GetFiles(reportDir, "SecKit-Report-*.json");
        if (jsonFiles.Length == 0)
        {
            Logger.Warning($"No SecKit JSON report files found in {reportDir}");
            return 0;
        }

        var regenerated = 0;
        foreach (var jsonFile in jsonFiles)
        {
            try
            {
                var json = File.ReadAllText(jsonFile);
                var report = System.Text.Json.JsonSerializer.Deserialize<SecurityReport>(json, JsonOptions);
                if (report == null) continue;

                var htmlPath = Path.ChangeExtension(jsonFile, ".html");
                var html = GenerateHtml(report);
                File.WriteAllText(htmlPath, html);
                regenerated++;
                Logger.Info($"Regenerated: {htmlPath}");
            }
            catch (Exception ex)
            {
                Logger.Error($"Failed to regenerate {jsonFile}: {ex.Message}");
            }
        }

        Logger.Info($"Regenerated {regenerated} HTML reports from {jsonFiles.Length} JSON files.");
        return regenerated;
    }

    /// <summary>Generates both HTML and JSON reports and saves to the output directory.</summary>
    public static async Task GenerateAsync(SecurityReport report, string outputDir, string format = "both")
    {
        Directory.CreateDirectory(outputDir);

        var timestamp = report.GeneratedAt.ToString("yyyyMMdd-HHmmss");
        var baseName = $"SecKit-Report-{timestamp}";

        if (format == "json" || format == "both")
        {
            var jsonPath = Path.Combine(outputDir, $"{baseName}.json");
            var json = JsonSerializer.Serialize(report, JsonOptions);
            await File.WriteAllTextAsync(jsonPath, json);
            Logger.Info($"JSON report saved: {jsonPath}");
        }

        if (format == "html" || format == "both")
        {
            var htmlPath = Path.Combine(outputDir, $"{baseName}.html");
            var html = GenerateHtml(report);
            await File.WriteAllTextAsync(htmlPath, html);
            Logger.Info($"HTML report saved: {htmlPath}");
        }
    }

    /// <summary>Generates an HTML report string from the security report.</summary>
    public static string GenerateHtml(SecurityReport report)
    {
        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html lang=\"en\">");
        sb.AppendLine("<head>");
        sb.AppendLine("<meta charset=\"UTF-8\">");
        sb.AppendLine("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
        sb.AppendLine($"<title>SecKit Security Report - {report.GeneratedAt:yyyy-MM-dd HH:mm}</title>");
        sb.AppendLine("<style>");
        sb.AppendLine(GetCssStyles());
        sb.AppendLine("</style>");
        sb.AppendLine("</head>");
        sb.AppendLine("<body>");

        // Header
        sb.AppendLine("<div class=\"container\">");
        sb.AppendLine("<div class=\"header\">");
        sb.AppendLine($"<h1>🔒 SecKit Security Report</h1>");
        sb.AppendLine($"<p>Generated: {report.GeneratedAt:yyyy-MM-dd HH:mm:ss UTC}</p>");
        sb.AppendLine($"<p>Tool Version: {report.ToolVersion} | Profile: {report.ScanProfile}</p>");
        sb.AppendLine($"<p>Duration: {report.TotalDuration.TotalMinutes:F1} minutes | Requests: {report.TotalRequestsSent} | Endpoints: {report.TotalEndpointsTested}</p>");
        sb.AppendLine("</div>");

        // Summary cards
        sb.AppendLine("<div class=\"summary\">");
        sb.AppendLine($"<div class=\"card critical\"><h3>Critical</h3><p>{report.CriticalCount}</p></div>");
        sb.AppendLine($"<div class=\"card high\"><h3>High</h3><p>{report.HighCount}</p></div>");
        sb.AppendLine($"<div class=\"card medium\"><h3>Medium</h3><p>{report.MediumCount}</p></div>");
        sb.AppendLine($"<div class=\"card low\"><h3>Low</h3><p>{report.LowCount}</p></div>");
        sb.AppendLine($"<div class=\"card info\"><h3>Info</h3><p>{report.InfoCount}</p></div>");
        sb.AppendLine($"<div class=\"card total\"><h3>Risk Score</h3><p>{report.RiskScore:F0}</p></div>");
        sb.AppendLine("</div>");

        // Targets
        sb.AppendLine("<h2>🎯 Targets</h2>");
        sb.AppendLine("<ul>");
        foreach (var url in report.TargetUrls)
            sb.AppendLine($"<li>{EscapeHtml(url)}</li>");
        sb.AppendLine("</ul>");

        // Module results
        sb.AppendLine("<h2>📋 Module Results</h2>");
        foreach (var module in report.ModuleResults)
        {
            var statusColor = module.Completed ? "#27ae60" : "#e74c3c";
            sb.AppendLine("<div class=\"module-section\">");
            sb.AppendLine($"<h3 style=\"color:{statusColor}\">{module.ModuleName} {(module.Completed ? "✅" : "❌")}</h3>");
            sb.AppendLine($"<p>Duration: {module.Duration.TotalSeconds:F1}s | Requests: {module.RequestsSent} | Endpoints: {module.EndpointsTested}</p>");
            if (!string.IsNullOrEmpty(module.ErrorMessage))
                sb.AppendLine($"<p class=\"error\">Error: {EscapeHtml(module.ErrorMessage)}</p>");

            if (module.Vulnerabilities.Count > 0)
            {
                sb.AppendLine("<table><thead><tr>");
                sb.AppendLine("<th>Severity</th><th>Type</th><th>URL</th><th>Parameter</th><th>Description</th><th>Remediation</th>");
                sb.AppendLine("</tr></thead><tbody>");

                foreach (var vuln in module.Vulnerabilities.OrderByDescending(v => SeverityOrder(v.Severity)))
                {
                    sb.AppendLine($"<tr class=\"severity-{vuln.Severity.ToLower()}\">");
                    sb.AppendLine($"<td><span class=\"badge badge-{vuln.Severity.ToLower()}\">{vuln.Severity}</span></td>");
                    sb.AppendLine($"<td>{EscapeHtml(vuln.Type)}</td>");
                    sb.AppendLine($"<td>{EscapeHtml(vuln.Url)}</td>");
                    sb.AppendLine($"<td>{EscapeHtml(vuln.Parameter)}</td>");
                    sb.AppendLine($"<td>{EscapeHtml(vuln.Description)}</td>");
                    sb.AppendLine($"<td>{EscapeHtml(vuln.Remediation)}</td>");
                    sb.AppendLine("</tr>");
                }

                sb.AppendLine("</tbody></table>");
            }
            else
            {
                sb.AppendLine("<p class=\"no-findings\">No vulnerabilities found.</p>");
            }
            sb.AppendLine("</div>");
        }

        // Footer
        sb.AppendLine("<div class=\"footer\">");
        sb.AppendLine("<p>Generated by SecKit v1.0.0 — .NET Security Toolkit</p>");
        sb.AppendLine("</div>");
        sb.AppendLine("</div>");
        sb.AppendLine("</body></html>");

        return sb.ToString();
    }

    /// <summary>Prints a real-time summary of a completed scan result to the console.</summary>
    public static void PrintConsoleSummary(ScanResult result)
    {
        Logger.WriteLine("", ConsoleColor.White);
        Logger.WriteLine($"╔══════════════════════════════════════════╗", ConsoleColor.Cyan);
        Logger.WriteLine($"║  {result.ModuleName} Results".PadRight(42) + "║", ConsoleColor.Cyan);
        Logger.WriteLine($"╠══════════════════════════════════════════╣", ConsoleColor.Cyan);
        Logger.WriteLine($"║  Duration:   {result.Duration.TotalSeconds,5:F1}s".PadRight(42) + "║", ConsoleColor.White);
        Logger.WriteLine($"║  Requests:   {result.RequestsSent,5}".PadRight(42) + "║", ConsoleColor.White);
        Logger.WriteLine($"║  Critical:   {result.CriticalCount,5}".PadRight(42) + "║", ConsoleColor.DarkRed);
        Logger.WriteLine($"║  High:       {result.HighCount,5}".PadRight(42) + "║", ConsoleColor.Red);
        Logger.WriteLine($"║  Medium:     {result.MediumCount,5}".PadRight(42) + "║", ConsoleColor.Yellow);
        Logger.WriteLine($"║  Low:        {result.LowCount,5}".PadRight(42) + "║", ConsoleColor.DarkYellow);
        Logger.WriteLine($"║  Info:       {result.InfoCount,5}".PadRight(42) + "║", ConsoleColor.Cyan);
        Logger.WriteLine($"╚══════════════════════════════════════════╝", ConsoleColor.Cyan);
        Logger.WriteLine("", ConsoleColor.White);
    }

    private static int SeverityOrder(string severity) => severity switch
    {
        "Critical" => 0, "High" => 1, "Medium" => 2, "Low" => 3, _ => 4
    };

    private static string EscapeHtml(string text) =>
        System.Net.WebUtility.HtmlEncode(text ?? "");

    private static string GetCssStyles() => @"
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #1a1a2e; color: #e0e0e0; line-height: 1.6; }
.container { max-width: 1200px; margin: 0 auto; padding: 20px; }
.header { background: linear-gradient(135deg, #16213e, #0f3460); padding: 30px; border-radius: 12px; margin-bottom: 30px; border: 1px solid #333; }
.header h1 { color: #e94560; font-size: 2em; margin-bottom: 10px; }
.header p { color: #a0a0b0; }
.summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 15px; margin-bottom: 30px; }
.card { padding: 20px; border-radius: 10px; text-align: center; border: 1px solid #333; }
.card h3 { font-size: 0.9em; margin-bottom: 8px; }
.card p { font-size: 2em; font-weight: bold; }
.card.critical { background: #2d1b1b; border-color: #e74c3c; color: #e74c3c; }
.card.high { background: #2d201b; border-color: #e67e22; color: #e67e22; }
.card.medium { background: #2d2d1b; border-color: #f1c40f; color: #f1c40f; }
.card.low { background: #1b2d1b; border-color: #2ecc71; color: #2ecc71; }
.card.info { background: #1b2d2d; border-color: #3498db; color: #3498db; }
.card.total { background: #1b1b2d; border-color: #9b59b6; color: #9b59b6; }
h2 { color: #e94560; margin: 25px 0 15px; border-bottom: 2px solid #333; padding-bottom: 8px; }
.module-section { background: #16213e; padding: 20px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #333; }
table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 0.9em; }
th { background: #0f3460; padding: 10px; text-align: left; font-weight: 600; color: #e94560; }
td { padding: 8px 10px; border-bottom: 1px solid #2a2a4a; }
tr:hover { background: rgba(233,69,96,0.05); }
.badge { display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 0.8em; font-weight: bold; }
.badge-critical { background: #e74c3c; color: white; }
.badge-high { background: #e67e22; color: white; }
.badge-medium { background: #f1c40f; color: #1a1a2e; }
.badge-low { background: #2ecc71; color: white; }
.badge-info { background: #3498db; color: white; }
.severity-critical { border-left: 4px solid #e74c3c; }
.severity-high { border-left: 4px solid #e67e22; }
.severity-medium { border-left: 4px solid #f1c40f; }
.severity-low { border-left: 4px solid #2ecc71; }
.severity-info { border-left: 4px solid #3498db; }
.no-findings { color: #2ecc71; padding: 15px; font-style: italic; }
.error { color: #e74c3c; }
.footer { text-align: center; color: #666; padding: 30px; margin-top: 30px; border-top: 1px solid #333; }
ul { list-style: none; padding: 0; }
ul li { background: #16213e; padding: 10px 15px; margin: 5px 0; border-radius: 5px; font-family: monospace; }
";
}
