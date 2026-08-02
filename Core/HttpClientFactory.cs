using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace SecKit.Core;

/// <summary>Factory for creating configured HttpClient instances with proxy, TLS, and header support.</summary>
public static class HttpClientFactory
{
    private static readonly string[] UserAgents = new[]
    {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
    };

    private static int _userAgentIndex;
    private static readonly Random _rng = new();

    /// <summary>Gets the next rotating user-agent string.</summary>
    public static string NextUserAgent()
    {
        var idx = Interlocked.Increment(ref _userAgentIndex) % UserAgents.Length;
        return UserAgents[Math.Abs(idx)];
    }

    private static HttpClientHandler CreateHandler(ConfigManager config)
    {
        var handler = new HttpClientHandler
        {
            AllowAutoRedirect = true,
            MaxAutomaticRedirections = 10,
            AutomaticDecompression = DecompressionMethods.All,
        };

        // TLS configuration
        if (config.TlsVersion.HasValue)
        {
            handler.SslProtocols = config.TlsVersion.Value switch
            {
                1 => System.Security.Authentication.SslProtocols.Tls12,
                2 => System.Security.Authentication.SslProtocols.Tls13,
                _ => System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13,
            };
        }

        // SSL certificate validation (allow self-signed for testing)
        handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) =>
        {
            if (config.AllowUntrustedCertificates)
                return true;
            return errors == SslPolicyErrors.None;
        };

        // Proxy support
        if (config.ProxyEnabled && !string.IsNullOrWhiteSpace(config.ProxyUrl))
        {
            handler.Proxy = new WebProxy(config.ProxyUrl);
            if (!string.IsNullOrWhiteSpace(config.ProxyUsername))
            {
                handler.Proxy.Credentials = new NetworkCredential(config.ProxyUsername, config.ProxyPassword);
                handler.UseProxy = true;
                handler.PreAuthenticate = true;
            }
        }

        return handler;
    }

    /// <summary>Creates a new HttpClient with the given configuration and custom headers.</summary>
    public static HttpClient Create(ConfigManager config, Dictionary<string, string>? extraHeaders = null)
    {
        var handler = CreateHandler(config);
        var client = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(config.TimeoutSeconds)
        };

        // Set rotating user-agent
        client.DefaultRequestHeaders.UserAgent.Clear();
        client.DefaultRequestHeaders.UserAgent.ParseAdd(NextUserAgent());

        // Custom headers from config
        foreach (var (key, value) in config.CustomHeaders)
        {
            client.DefaultRequestHeaders.TryAddWithoutValidation(key, value);
        }

        // Extra headers for specific requests
        if (extraHeaders != null)
        {
            foreach (var (key, value) in extraHeaders)
            {
                client.DefaultRequestHeaders.TryAddWithoutValidation(key, value);
            }
        }

        // Auth cookie
        if (!string.IsNullOrWhiteSpace(config.AuthCookie))
        {
            client.DefaultRequestHeaders.TryAddWithoutValidation("Cookie", config.AuthCookie);
        }

        // Auth token
        if (!string.IsNullOrWhiteSpace(config.AuthToken))
        {
            client.DefaultRequestHeaders.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", config.AuthToken);
        }

        return client;
    }

    /// <summary>Creates a basic HttpClient with minimal configuration for quick requests.</summary>
    public static HttpClient CreateSimple(int timeoutSeconds = 15)
    {
        return new HttpClient(new HttpClientHandler
        {
            AllowAutoRedirect = true,
            AutomaticDecompression = DecompressionMethods.All,
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true
        })
        {
            Timeout = TimeSpan.FromSeconds(timeoutSeconds)
        };
    }
}
