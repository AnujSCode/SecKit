using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using HtmlAgilityPack;
using SecKit.Core;
using SecKit.Models;

namespace SecKit.Modules.SiteMapper;

/// <summary>Web crawler that discovers pages, forms, links, JS files, and API endpoints.</summary>
public class Crawler
{
    private readonly HttpClient _client;
    private readonly ConfigManager _config;
    private readonly HashSet<string> _visitedUrls = new();
    private readonly ConcurrentDictionary<string, PageInfo> _discovered = new();
    private int _maxDepth;
    private int _maxPages;
    private Uri _baseUri = null!;

    public Crawler(HttpClient client, ConfigManager config)
    {
        _client = client;
        _config = config;
        _maxDepth = config.MaxDepth;
        _maxPages = config.MaxPages;
    }

    /// <summary>Represents a discovered page with its metadata.</summary>
    public record PageInfo(string Url, int Depth, string Title, List<string> Links, List<string> Forms,
        List<string> Scripts, List<string> ApiEndpoints, int StatusCode);

    /// <summary>Crawls a website starting from the given URL and discovers all reachable resources.</summary>
    public async Task<ScanResult> CrawlAsync(string startUrl)
    {
        var result = new ScanResult
        {
            ModuleName = "Site Mapper (Crawler)",
            TargetUrl = startUrl,
            StartTime = DateTime.UtcNow
        };

        try
        {
            _baseUri = new Uri(startUrl);
            _visitedUrls.Clear();
            _discovered.Clear();

            Logger.Info($"Crawling {startUrl} (max depth: {_maxDepth}, max pages: {_maxPages})...");

            await CrawlPageAsync(startUrl, 0);

            result.EndpointsTested = _discovered.Count;
            result.RequestsSent = _visitedUrls.Count;
            result.Completed = true;

            Logger.WriteLine($"\n📊 Crawl Results:", ConsoleColor.Cyan);
            Logger.WriteLine($"  Pages discovered: {_discovered.Count}", ConsoleColor.White);
            Logger.WriteLine($"  Forms found: {_discovered.Values.Sum(p => p.Forms.Count)}", ConsoleColor.White);
            Logger.WriteLine($"  JS files found: {_discovered.Values.Sum(p => p.Scripts.Count)}", ConsoleColor.White);
            Logger.WriteLine($"  API endpoints: {_discovered.Values.Sum(p => p.ApiEndpoints.Count)}", ConsoleColor.White);

            // Report JS files
            foreach (var jsFile in _discovered.Values.SelectMany(p => p.Scripts).Distinct())
            {
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "JavaScript File",
                    Severity = "Info",
                    Url = jsFile,
                    Parameter = "script",
                    Description = "Discovered JavaScript file during crawl.",
                    Remediation = "Review JS files for sensitive data exposure.",
                    Module = "Crawler",
                    Confidence = 100
                });
            }

            // Report API endpoints
            foreach (var apiEndpoint in _discovered.Values.SelectMany(p => p.ApiEndpoints).Distinct())
            {
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "API Endpoint",
                    Severity = "Info",
                    Url = apiEndpoint,
                    Parameter = "endpoint",
                    Description = "Discovered API endpoint during crawl.",
                    Remediation = "Ensure API endpoints require authentication and are properly secured.",
                    Module = "Crawler",
                    Confidence = 100
                });
            }

            // Report forms that might be interesting
            foreach (var page in _discovered.Values.Where(p => p.Forms.Count > 0))
            {
                foreach (var form in page.Forms)
                {
                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = "HTML Form",
                        Severity = "Low",
                        Url = page.Url,
                        Parameter = "form",
                        Description = $"Discovered form: {form}",
                        Remediation = "Ensure forms have CSRF protection, input validation, and proper encoding.",
                        Module = "Crawler",
                        Confidence = 100
                    });
                }
            }
        }
        catch (Exception ex)
        {
            result.ErrorMessage = ex.Message;
            Logger.Error($"Crawler failed: {ex.Message}");
        }

        result.EndTime = DateTime.UtcNow;
        return result;
    }

    private async Task CrawlPageAsync(string url, int depth)
    {
        if (depth > _maxDepth) return;
        if (_discovered.Count >= _maxPages) return;

        var normalized = NormalizeUrl(url);
        if (!_visitedUrls.Add(normalized)) return;

        try
        {
            Logger.Debug($"Crawling [{depth}] {normalized}");
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(_config.TimeoutSeconds));
            var response = await _client.GetAsync(normalized, cts.Token);

            var contentType = response.Content.Headers.ContentType?.MediaType ?? "";
            if (!contentType.Contains("html") && !contentType.Contains("text"))
            {
                // Non-HTML resource, just record it
                Logger.Debug($"  Non-HTML: {contentType} -> {normalized}");
                return;
            }

            var html = await response.Content.ReadAsStringAsync(cts.Token);
            var doc = new HtmlDocument();
            doc.LoadHtml(html);

            var title = doc.DocumentNode.SelectSingleNode("//title")?.InnerText?.Trim() ?? "(no title)";
            var links = new List<string>();
            var forms = new List<string>();
            var scripts = new List<string>();
            var apiEndpoints = new List<string>();

            // Extract links
            var linkNodes = doc.DocumentNode.SelectNodes("//a[@href]");
            if (linkNodes != null)
            {
                foreach (var link in linkNodes)
                {
                    var href = link.GetAttributeValue("href", "");
                    if (string.IsNullOrWhiteSpace(href)) continue;
                    href = href.Trim();
                    if (href.StartsWith("#") || href.StartsWith("javascript:") || href.StartsWith("mailto:") || href.StartsWith("tel:"))
                        continue;

                    var resolved = ResolveUrl(normalized, href);
                    if (IsSameDomain(resolved))
                    {
                        links.Add(resolved);
                    }
                }
            }

            // Extract forms
            var formNodes = doc.DocumentNode.SelectNodes("//form");
            if (formNodes != null)
            {
                foreach (var form in formNodes)
                {
                    var action = form.GetAttributeValue("action", "");
                    var method = form.GetAttributeValue("method", "GET");
                    var inputs = form.SelectNodes(".//input[@name]");
                    var inputNames = inputs?.Select(i => i.GetAttributeValue("name", "")).Where(n => !string.IsNullOrEmpty(n)) ?? Enumerable.Empty<string>();
                    var formDesc = $"{method} {action} [{string.Join(", ", inputNames)}]";
                    forms.Add(formDesc);
                }
            }

            // Extract scripts
            var scriptNodes = doc.DocumentNode.SelectNodes("//script[@src]");
            if (scriptNodes != null)
            {
                foreach (var script in scriptNodes)
                {
                    var src = script.GetAttributeValue("src", "");
                    if (!string.IsNullOrWhiteSpace(src))
                    {
                        scripts.Add(ResolveUrl(normalized, src));
                    }
                }
            }

            // Find API endpoints in inline scripts and links
            var apiPatterns = new[]
            {
                @"['""](https?://[^'""]*/api/[^'""]*)['""]",
                @"['""](/api/[^'""]*)['""]",
                @"fetch\s*\(\s*['""]([^'""]*)['""]",
                @"axios\.(?:get|post|put|delete|patch)\s*\(\s*['""]([^'""]*)['""]",
            };

            foreach (var pattern in apiPatterns)
            {
                foreach (Match m in Regex.Matches(html, pattern, RegexOptions.IgnoreCase))
                {
                    var endpoint = m.Groups[1].Value;
                    if (!string.IsNullOrWhiteSpace(endpoint))
                    {
                        apiEndpoints.Add(endpoint.StartsWith("http") ? endpoint : ResolveUrl(normalized, endpoint));
                    }
                }
            }

            // Also check link hrefs for API patterns
            var apiLinkNodes = doc.DocumentNode.SelectNodes("//link[@href]");
            if (apiLinkNodes != null)
            {
                foreach (var link in apiLinkNodes)
                {
                    var href = link.GetAttributeValue("href", "");
                    if (href.Contains("/api/", StringComparison.OrdinalIgnoreCase) ||
                        href.Contains("swagger", StringComparison.OrdinalIgnoreCase) ||
                        href.Contains("openapi", StringComparison.OrdinalIgnoreCase))
                    {
                        apiEndpoints.Add(ResolveUrl(normalized, href));
                    }
                }
            }

            _discovered[normalized] = new PageInfo(normalized, depth, title,
                links, forms, scripts, apiEndpoints.Distinct().ToList(), (int)response.StatusCode);

            // Crawl discovered links (BFS-like)
            if (depth < _maxDepth && _discovered.Count < _maxPages)
            {
                var unvisitedLinks = links.Where(l => !_visitedUrls.Contains(l)).Take(20).ToList();
                foreach (var link in unvisitedLinks)
                {
                    if (_discovered.Count >= _maxPages) break;
                    await CrawlPageAsync(link, depth + 1);
                }
            }
        }
        catch (TaskCanceledException)
        {
            Logger.Debug($"  Timeout crawling: {normalized}");
        }
        catch (Exception ex)
        {
            Logger.Debug($"  Error crawling {normalized}: {ex.Message}");
        }
    }

    private string NormalizeUrl(string url)
    {
        try
        {
            var uri = new Uri(url);
            var normalized = uri.GetLeftPart(UriPartial.Path);
            if (!string.IsNullOrWhiteSpace(uri.Query))
                normalized += uri.Query;
            return normalized.TrimEnd('/');
        }
        catch
        {
            return url;
        }
    }

    private string ResolveUrl(string baseUrl, string relativeOrAbsolute)
    {
        if (relativeOrAbsolute.StartsWith("http://") || relativeOrAbsolute.StartsWith("https://"))
            return relativeOrAbsolute;
        try
        {
            return new Uri(new Uri(baseUrl), relativeOrAbsolute).ToString();
        }
        catch
        {
            return baseUrl;
        }
    }

    private bool IsSameDomain(string url)
    {
        try
        {
            var uri = new Uri(url);
            return uri.Host == _baseUri.Host ||
                   uri.Host.EndsWith("." + _baseUri.Host) ||
                   _baseUri.Host.EndsWith("." + uri.Host);
        }
        catch
        {
            return false;
        }
    }
}
