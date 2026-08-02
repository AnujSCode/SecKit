namespace SecKit.Models;

/// <summary>Full security report aggregating all scan results with metadata.</summary>
public class SecurityReport
{
    public string ReportId { get; set; } = Guid.NewGuid().ToString("N")[..12];
    public DateTime GeneratedAt { get; set; } = DateTime.UtcNow;
    public string ToolVersion { get; set; } = "1.0.0";
    public string ScanProfile { get; set; } = "medium";
    public List<string> TargetUrls { get; set; } = new();
    public DateTime ScanStartTime { get; set; }
    public DateTime ScanEndTime { get; set; }
    public TimeSpan TotalDuration => ScanEndTime - ScanStartTime;
    public List<ScanResult> ModuleResults { get; set; } = new();
    public List<Vulnerability> AllVulnerabilities { get; set; } = new();

    public int TotalVulnerabilities => AllVulnerabilities.Count;
    public int CriticalCount => AllVulnerabilities.Count(v => v.Severity == "Critical");
    public int HighCount => AllVulnerabilities.Count(v => v.Severity == "High");
    public int MediumCount => AllVulnerabilities.Count(v => v.Severity == "Medium");
    public int LowCount => AllVulnerabilities.Count(v => v.Severity == "Low");
    public int InfoCount => AllVulnerabilities.Count(v => v.Severity == "Info");

    public int TotalRequestsSent => ModuleResults.Sum(r => r.RequestsSent);
    public int TotalEndpointsTested => ModuleResults.Sum(r => r.EndpointsTested);

    public double RiskScore => (CriticalCount * 10 + HighCount * 5 + MediumCount * 3 + LowCount * 1) * 1.0;
}
