using System.Security.Authentication;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Configuration;

namespace SecKit.Core;

/// <summary>Manages configuration loaded from appsettings.json with typed accessors.</summary>
public class ConfigManager
{
    private readonly IConfiguration _config;

    public ConfigManager(string configPath = "appsettings.json")
    {
        if (!File.Exists(configPath))
        {
            CreateDefaultConfig(configPath);
        }

        _config = new ConfigurationBuilder()
            .SetBasePath(Directory.GetCurrentDirectory())
            .AddJsonFile(configPath, optional: false, reloadOnChange: false)
            .Build();
    }

    // --- Target settings ---
    public List<string> TargetUrls =>
        _config.GetSection("targets:urls").Get<List<string>>() ?? new List<string>();
    public string AuthToken => _config["targets:authToken"] ?? "";
    public string AuthCookie => _config["targets:cookies:session"] ?? "";

    // --- Scan profile settings ---
    public int MaxDepth => _config.GetValue<int>($"scanProfiles:{ActiveProfile}:maxDepth", 4);
    public int MaxPages => _config.GetValue<int>($"scanProfiles:{ActiveProfile}:maxPages", 200);
    public int TimeoutSeconds => _config.GetValue<int>($"scanProfiles:{ActiveProfile}:timeoutSeconds", 15);
    public int Threads => _config.GetValue<int>($"scanProfiles:{ActiveProfile}:threads", 10);
    public int FuzzParams => _config.GetValue<int>($"scanProfiles:{ActiveProfile}:fuzzParams", 100);
    public int PortRangeStart => _config.GetValue<int>($"scanProfiles:{ActiveProfile}:portRangeStart", 1);
    public int PortRangeEnd => _config.GetValue<int>($"scanProfiles:{ActiveProfile}:portRangeEnd", 5000);
    public string ActiveProfile { get; set; } = "medium";

    // --- Proxy settings ---
    public bool ProxyEnabled => _config.GetValue<bool>("proxy:enabled", false);
    public string? ProxyUrl => _config["proxy:url"];
    public string ProxyType => _config["proxy:type"] ?? "HTTP";
    public string? ProxyUsername => _config["proxy:username"];
    public string? ProxyPassword => _config["proxy:password"];

    // --- Custom headers ---
    public Dictionary<string, string> CustomHeaders
    {
        get
        {
            var dict = new Dictionary<string, string>();
            var section = _config.GetSection("customHeaders");
            foreach (var child in section.GetChildren())
            {
                dict[child.Key] = child.Value ?? "";
            }
            return dict;
        }
    }

    // --- Output settings ---
    public string OutputDirectory => _config["output:directory"] ?? "./reports";
    public string OutputFormat => _config["output:format"] ?? "both";
    public bool IncludeRawResponse => _config.GetValue<bool>("output:includeRawResponse", false);

    // --- TLS / SSL ---
    public int? TlsVersion
    {
        get
        {
            var v = _config["tls:minimumVersion"];
            return v switch
            {
                "Tls12" => 1,
                "Tls13" => 2,
                _ => null
            };
        }
    }
    public bool AllowUntrustedCertificates => _config.GetValue<bool>("tls:allowUntrusted", false);

    private static void CreateDefaultConfig(string path)
    {
        var defaultConfig = new
        {
            targets = new
            {
                urls = new[] { "http://localhost:8080" },
                authToken = "",
                cookies = new { session = "" }
            },
            scanProfiles = new
            {
                light = new { maxDepth = 2, maxPages = 50, timeoutSeconds = 10, threads = 5, fuzzParams = 20, portRangeStart = 1, portRangeEnd = 1024 },
                medium = new { maxDepth = 4, maxPages = 200, timeoutSeconds = 15, threads = 10, fuzzParams = 100, portRangeStart = 1, portRangeEnd = 5000 },
                deep = new { maxDepth = 8, maxPages = 1000, timeoutSeconds = 30, threads = 20, fuzzParams = 500, portRangeStart = 1, portRangeEnd = 65535 }
            },
            proxy = new { enabled = false, url = "", type = "HTTP", username = "", password = "" },
            customHeaders = new Dictionary<string, string>
            {
                ["User-Agent"] = "SecKit/1.0",
                ["Accept"] = "*/*"
            },
            output = new { directory = "./reports", format = "both", includeRawResponse = false }
        };

        var json = JsonSerializer.Serialize(defaultConfig, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(path, json);
    }
}
