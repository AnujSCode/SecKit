using System.Collections.Concurrent;
using SecKit.Core;
using SecKit.Models;

namespace SecKit.Modules.SiteMapper;

/// <summary>Fuzzes discovered endpoints with wordlists to find hidden paths and files.</summary>
public class Fuzzer
{
    private readonly HttpClient _client;
    private readonly ConfigManager _config;
    private readonly int _threads;

    // Common wordlist for path fuzzing
    private static readonly string[] CommonPaths =
    {
        "admin", "login", "logout", "dashboard", "api", "api/v1", "api/v2",
        "graphql", "swagger", "api-docs", "docs", "documentation",
        "backup", "backups", "backup.zip", "backup.sql", "backup.tar.gz",
        "config", "configuration", "config.json", "config.yml", "config.yaml",
        ".env", ".env.backup", ".env.example", ".env.local", ".env.production",
        ".git", ".git/config", ".gitignore", ".git/HEAD",
        ".svn", ".svn/entries", ".hg", ".bzr",
        ".DS_Store", "Thumbs.db", "desktop.ini",
        "wp-admin", "wp-login.php", "wp-config.php", "wp-content",
        "xmlrpc.php", "wp-json", "wp-json/wp/v2/users",
        "administrator", "joomla", "drupal",
        "phpmyadmin", "phpMyAdmin", "pma", "mysql", "adminer",
        "db", "database", "phpinfo.php", "info.php", "test.php",
        "server-status", "server-info", "status",
        "actuator", "actuator/health", "actuator/info", "actuator/env",
        "health", "healthz", "readyz", "metrics",
        "debug", "debug/default", "trace", "profiler",
        "console", "terminal", "shell", "cmd",
        "upload", "uploads", "files", "download", "downloads",
        "logs", "log", "error.log", "access.log", "debug.log",
        "tmp", "temp", "cache", "caches",
        "old", "new", "test", "testing", "dev", "development",
        "staging", "stage", "prod", "production",
        "private", "internal", "secret", "secrets", "hidden",
        "assets", "static", "public", "resources",
        "images", "img", "css", "js", "fonts", "media",
        "robots.txt", "sitemap.xml", "crossdomain.xml", "security.txt",
        "favicon.ico", "apple-touch-icon.png",
        ".well-known", ".well-known/security.txt", ".well-known/openid-configuration",
        "vendor", "node_modules", "bower_components",
        "composer.json", "composer.lock", "package.json", "package-lock.json",
        "yarn.lock", "Gemfile", "Gemfile.lock", "requirements.txt",
        "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
        ".dockerignore", ".gitlab-ci.yml", ".travis.yml", "Jenkinsfile",
        "Makefile", "CMakeLists.txt", "build.gradle", "pom.xml",
        "README.md", "CHANGELOG.md", "LICENSE", "CONTRIBUTING.md",
        "cgi-bin", "cgi", "bin", "script", "scripts",
        "install", "setup", "init", "reset",
        "crontab", "cron", "scheduler",
        "web.config", "Web.config", "app.config",
        "web.xml", "server.xml", "context.xml",
        "WEB-INF", "WEB-INF/web.xml", "META-INF",
        "webpack.config.js", "vite.config.js", "rollup.config.js",
        "tsconfig.json", ".babelrc", ".eslintrc",
        ".aws", ".azure", ".gcloud",
        "credentials", "credentials.json", "token", "tokens",
        "keys", "key", "cert", "certificate", "pem",
    };

    // Common parameter names for parameter fuzzing
    private static readonly string[] CommonParams =
    {
        "id", "page", "action", "cmd", "command", "exec", "execute",
        "file", "filename", "path", "dir", "directory", "folder",
        "url", "redirect", "next", "return", "callback", "back",
        "query", "search", "q", "s", "keyword", "filter",
        "user", "username", "name", "email", "password", "pass", "passwd",
        "token", "auth", "key", "api_key", "apikey", "secret",
        "debug", "test", "admin", "root", "sudo",
        "type", "format", "output", "view", "template",
        "lang", "language", "locale", "country", "region",
        "sort", "order", "limit", "offset", "page_size",
        "include", "exclude", "fields", "select", "where",
    };

    public Fuzzer(HttpClient client, ConfigManager config)
    {
        _client = client;
        _config = config;
        _threads = config.Threads;
    }

    /// <summary>Fuzzes a base URL for hidden directories and files.</summary>
    public async Task<ScanResult> FuzzAsync(string baseUrl)
    {
        var result = new ScanResult
        {
            ModuleName = "Directory/File Fuzzer",
            TargetUrl = baseUrl,
            StartTime = DateTime.UtcNow
        };

        try
        {
            var fuzzCount = Math.Min(_config.FuzzParams, CommonPaths.Length);
            var paths = CommonPaths.Take(fuzzCount);

            Logger.Info($"Fuzzing {baseUrl} with {fuzzCount} paths ({_threads} threads)...");

            var foundPaths = new ConcurrentBag<(string Path, int StatusCode, long ContentLength)>();
            using var semaphore = new SemaphoreSlim(_threads);
            var tasks = new List<Task>();

            foreach (var path in paths)
            {
                await semaphore.WaitAsync();
                var currentPath = path;

                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        var testUrl = CombineUrl(baseUrl, currentPath);
                        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                        var response = await _client.GetAsync(testUrl, cts.Token);
                        var statusCode = (int)response.StatusCode;

                        result.RequestsSent++;

                        if (statusCode == 200 || statusCode == 301 || statusCode == 302 || statusCode == 403)
                        {
                            var contentLength = response.Content.Headers.ContentLength ?? 0;
                            foundPaths.Add((currentPath, statusCode, contentLength));

                            var color = statusCode switch
                            {
                                200 => ConsoleColor.Green,
                                301 or 302 => ConsoleColor.Cyan,
                                403 => ConsoleColor.Yellow,
                                _ => ConsoleColor.Gray
                            };

                            Logger.WriteLine($"  [{statusCode}] /{currentPath}", color);
                        }
                    }
                    catch { /* Ignore unreachable paths */ }
                    finally
                    {
                        semaphore.Release();
                    }
                }));

                // Small delay to avoid overwhelming the server
                if (tasks.Count % 10 == 0)
                    await Task.Delay(50);
            }

            await Task.WhenAll(tasks);

            result.EndpointsTested = fuzzCount;

            foreach (var (path, statusCode, contentLength) in foundPaths.OrderBy(p => p.StatusCode))
            {
                var severity = path switch
                {
                    string p when p.Contains(".env") || p.Contains("backup") || p.Contains("config") => "High",
                    string p when p.Contains(".git") || p.Contains("admin") || p.Contains("phpmyadmin") => "Medium",
                    _ => "Low"
                };

                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "Discovered Resource",
                    Severity = severity,
                    Url = CombineUrl(baseUrl, path),
                    Parameter = "path",
                    Payload = path,
                    Description = $"Found {path} (HTTP {statusCode}, {contentLength} bytes) — may expose sensitive info.",
                    Remediation = statusCode == 403
                        ? "Verify directory listing is disabled and access controls are correct."
                        : "Review if this resource should be publicly accessible. Restrict access as needed.",
                    Module = "Fuzzer",
                    Confidence = 100
                });
            }

            Logger.Info($"Fuzzing complete: {foundPaths.Count} resources found.");
            result.Completed = true;
        }
        catch (Exception ex)
        {
            result.ErrorMessage = ex.Message;
            Logger.Error($"Fuzzer failed: {ex.Message}");
        }

        result.EndTime = DateTime.UtcNow;
        return result;
    }

    /// <summary>Fuzzes parameters on discovered endpoints for common injection points.</summary>
    public async Task<ScanResult> FuzzParametersAsync(string targetUrl, IEnumerable<string>? endpoints = null)
    {
        var result = new ScanResult
        {
            ModuleName = "Parameter Fuzzer",
            TargetUrl = targetUrl,
            StartTime = DateTime.UtcNow
        };

        try
        {
            var urls = new List<string> { targetUrl };
            if (endpoints != null) urls.AddRange(endpoints);

            var foundParams = new ConcurrentBag<(string Url, string Param)>();
            using var semaphore = new SemaphoreSlim(_threads);
            var tasks = new List<Task>();

            foreach (var url in urls.Distinct())
            {
                foreach (var param in CommonParams.Take(Math.Min(_config.FuzzParams, 30)))
                {
                    await semaphore.WaitAsync();
                    var currentUrl = url;
                    var currentParam = param;

                    tasks.Add(Task.Run(async () =>
                    {
                        try
                        {
                            var testUrl = AppendParam(currentUrl, currentParam, "FUZZ");
                            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                            var response = await _client.GetAsync(testUrl, cts.Token);

                            result.RequestsSent++;
                            var body = await response.Content.ReadAsStringAsync(cts.Token);

                            // Check if the parameter seems to be processed
                            if (body.Contains("FUZZ") || body.Contains("fuzz"))
                            {
                                foundParams.Add((currentUrl, currentParam));
                                Logger.WriteLine($"  ✓ Parameter '{currentParam}' reflected at {currentUrl}", ConsoleColor.Green);
                            }
                        }
                        catch { }
                        finally
                        {
                            semaphore.Release();
                        }
                    }));
                }
            }

            await Task.WhenAll(tasks);

            foreach (var (url, param) in foundParams)
            {
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "Reflective Parameter",
                    Severity = "Low",
                    Url = url,
                    Parameter = param,
                    Description = $"Parameter '{param}' reflects user input — potential XSS/SSTI/Injection target.",
                    Remediation = "Validate and encode all user input. Test this parameter for injection vulnerabilities.",
                    Module = "Fuzzer",
                    Confidence = 70
                });
            }

            result.EndpointsTested = urls.Count;
            result.Completed = true;
        }
        catch (Exception ex)
        {
            result.ErrorMessage = ex.Message;
            Logger.Error($"Parameter fuzzer failed: {ex.Message}");
        }

        result.EndTime = DateTime.UtcNow;
        return result;
    }

    private static string CombineUrl(string baseUrl, string path)
    {
        var trimmed = baseUrl.TrimEnd('/');
        return $"{trimmed}/{path.TrimStart('/')}";
    }

    private static string AppendParam(string url, string key, string value)
    {
        var separator = url.Contains('?') ? "&" : "?";
        return $"{url}{separator}{Uri.EscapeDataString(key)}={Uri.EscapeDataString(value)}";
    }
}
