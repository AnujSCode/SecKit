using System.Collections.Concurrent;
using System.Net;
using SecKit.Core;
using SecKit.Models;

namespace SecKit.Modules.TrafficAnalysis;

/// <summary>Enumerates subdomains of a target domain using DNS resolution and wordlists.</summary>
public class SubdomainEnumerator
{
    private readonly ConfigManager _config;
    private readonly int _threads;

    // Comprehensive subdomain wordlist
    private static readonly string[] SubdomainWordlist =
    {
        "www", "mail", "remote", "blog", "webmail", "server",
        "ns1", "ns2", "ns3", "ns4", "smtp", "secure", "vpn",
        "m", "shop", "ftp", "api", "dev", "develop", "development",
        "staging", "stage", "test", "testing", "qa", "uat", "demo",
        "admin", "administrator", "portal", "intranet", "extranet",
        "apps", "app", "web", "www2", "www3",
        "cdn", "static", "assets", "media", "images", "img", "files",
        "docs", "documentation", "support", "help", "helpdesk",
        "status", "monitor", "monitoring", "metrics", "logs", "log",
        "git", "svn", "ci", "jenkins", "build", "deploy",
        "jira", "confluence", "wiki",
        "calendar", "drive", "cloud",
        "db", "database", "mysql", "sql", "redis", "elastic",
        "search", "solr", "kibana", "grafana", "prometheus",
        "docker", "registry", "k8s", "kubernetes",
        "auth", "login", "sso", "oauth", "saml", "ldap",
        "api", "api-v1", "api-v2", "rest", "graphql", "ws",
        "webhook", "webhooks", "hook", "hooks", "callback",
        "payment", "payments", "billing", "invoice", "checkout",
        "store", "shop", "cart", "products", "catalog",
        "chat", "messenger", "im",
        "news", "newsletter", "updates",
        "events", "register", "registration", "signup",
        "partner", "partners", "affiliate", "affiliates",
        "investor", "investors", "press", "media",
        "careers", "jobs", "career", "hr",
        "corp", "corporate", "about", "contact",
        "mystaging", "mydev", "myadmin",
        "sandbox", "dev1", "dev2", "test1", "test2",
        "old", "new", "beta", "alpha", "v1", "v2",
        "origin", "edge", "proxy", "lb", "loadbalancer",
        "firewall", "fw", "gateway",
        "backup", "storage", "nas", "share",
        "print", "printer", "scanner",
        "phone", "voip", "sip",
        "travis", "circleci", "drone",
    };

    public SubdomainEnumerator(ConfigManager config)
    {
        _config = config;
        _threads = config.Threads;
    }

    /// <summary>Enumerates subdomains for a target domain.</summary>
    public async Task<ScanResult> EnumerateAsync(string domain)
    {
        var result = new ScanResult
        {
            ModuleName = "Subdomain Enumerator",
            TargetUrl = domain,
            StartTime = DateTime.UtcNow
        };

        try
        {
            // Clean domain
            domain = domain.Replace("https://", "").Replace("http://", "").TrimEnd('/');
            if (domain.Contains('/')) domain = domain.Split('/')[0];
            if (domain.Contains(':')) domain = domain.Split(':')[0];
            // Remove www. prefix if present
            if (domain.StartsWith("www.", StringComparison.OrdinalIgnoreCase))
                domain = domain[4..];

            Logger.Info($"Enumerating subdomains for {domain}...");

            var foundSubdomains = new ConcurrentBag<(string Subdomain, string Ip)>();
            using var semaphore = new SemaphoreSlim(_threads);
            var tasks = new List<Task>();

            foreach (var sub in SubdomainWordlist)
            {
                await semaphore.WaitAsync();
                var currentSub = sub;

                tasks.Add(Task.Run(() =>
                {
                    try
                    {
                        var hostname = $"{currentSub}.{domain}";
                        var addresses = Dns.GetHostAddresses(hostname);

                        foreach (var addr in addresses.Where(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork))
                        {
                            foundSubdomains.Add((hostname, addr.ToString()));
                            Logger.WriteLine($"  ✓ {hostname,-45} {addr}", ConsoleColor.Green);
                        }
                    }
                    catch
                    {
                        // Subdomain not found — expected for most entries
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                }));
            }

            await Task.WhenAll(tasks);

            result.EndpointsTested = SubdomainWordlist.Length;
            result.RequestsSent = SubdomainWordlist.Length;

            var sorted = foundSubdomains.OrderBy(s => s.Subdomain).ToList();

            Logger.WriteLine($"\n📊 Subdomain Enumeration Results:", ConsoleColor.Cyan);
            Logger.WriteLine($"  Total checked: {SubdomainWordlist.Length}", ConsoleColor.White);
            Logger.WriteLine($"  Subdomains found: {sorted.Count}", ConsoleColor.Green);

            foreach (var (subdomain, ip) in sorted)
            {
                var severity = subdomain switch
                {
                    string s when s.Contains("admin") || s.Contains("db") => "Medium",
                    string s when s.Contains("dev") || s.Contains("test") || s.Contains("staging") => "Medium",
                    string s when s.Contains("jenkins") || s.Contains("git") || s.Contains("ci") => "Medium",
                    _ => "Low"
                };

                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "Discovered Subdomain",
                    Severity = severity,
                    Url = $"https://{subdomain}",
                    Parameter = "subdomain",
                    Payload = ip,
                    Description = $"Subdomain '{subdomain}' resolved to {ip}.",
                    Remediation = subdomain.Contains("dev") || subdomain.Contains("test") || subdomain.Contains("staging")
                        ? "Ensure development/staging subdomains are not publicly accessible or are properly authenticated."
                        : "Review if this subdomain should be public. Remove unnecessary DNS records.",
                    Module = "SubdomainEnumerator",
                    Confidence = 100
                });
            }

            result.Completed = true;
        }
        catch (Exception ex)
        {
            result.ErrorMessage = ex.Message;
            Logger.Error($"Subdomain enumeration failed: {ex.Message}");
        }

        result.EndTime = DateTime.UtcNow;
        return result;
    }
}
