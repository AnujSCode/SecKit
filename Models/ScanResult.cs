namespace SecKit.Models;

/// <summary>Represents the result of a single scan module execution.</summary>
public class ScanResult
{
    public string ModuleName { get; set; } = string.Empty;
    public string TargetUrl { get; set; } = string.Empty;
    public DateTime StartTime { get; set; }
    public DateTime EndTime { get; set; }
    public TimeSpan Duration => EndTime - StartTime;
    public List<Vulnerability> Vulnerabilities { get; set; } = new();
    public int RequestsSent { get; set; }
    public int EndpointsTested { get; set; }
    public bool Completed { get; set; }
    public string? ErrorMessage { get; set; }

    public int CriticalCount => Vulnerabilities.Count(v => v.Severity == "Critical");
    public int HighCount => Vulnerabilities.Count(v => v.Severity == "High");
    public int MediumCount => Vulnerabilities.Count(v => v.Severity == "Medium");
    public int LowCount => Vulnerabilities.Count(v => v.Severity == "Low");
    public int InfoCount => Vulnerabilities.Count(v => v.Severity == "Info");
}
