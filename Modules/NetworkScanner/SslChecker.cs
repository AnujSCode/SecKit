#pragma warning disable CS0618, SYSLIB0039
using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using SecKit.Core;
using SecKit.Models;

namespace SecKit.Modules.NetworkScanner;

/// <summary>Checks SSL/TLS configuration, certificates, and cipher suites for target hosts.</summary>
public class SslChecker
{
    private readonly ConfigManager _config;

    public SslChecker(ConfigManager config)
    {
        _config = config;
    }

    /// <summary>Analyzes SSL/TLS configuration for a target host.</summary>
    public async Task<ScanResult> CheckAsync(string targetUrl)
    {
        var result = new ScanResult
        {
            ModuleName = "SSL/TLS Checker",
            TargetUrl = targetUrl,
            StartTime = DateTime.UtcNow
        };

        try
        {
            var host = ExtractHost(targetUrl);
            result.EndpointsTested = 1;

            Logger.Info($"Checking SSL/TLS for {host}...");

            // Check certificate via HTTPS connection
            X509Certificate2? cert = null;
            SslProtocols negotiatedProtocol = SslProtocols.None;

            try
            {
                using var tcpClient = new TcpClient();
                await tcpClient.ConnectAsync(host, 443);

                using var sslStream = new SslStream(
                    tcpClient.GetStream(),
                    false,
                    (sender, certificate, chain, sslPolicyErrors) =>
                    {
                        cert = certificate as X509Certificate2 ?? new X509Certificate2(certificate?.Export(X509ContentType.Cert) ?? Array.Empty<byte>());
                        return true; // Accept for analysis
                    });

                await sslStream.AuthenticateAsClientAsync(host);
                negotiatedProtocol = sslStream.SslProtocol;
                result.RequestsSent++;

                Logger.WriteLine($"  ✓ SSL/TLS connection established ({negotiatedProtocol})", ConsoleColor.Green);
            }
            catch (Exception ex)
            {
                Logger.WriteLine($"  ✗ SSL/TLS connection failed: {ex.Message}", ConsoleColor.Red);
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "SSL/TLS Connection Failed",
                    Severity = "High",
                    Url = $"https://{host}:443",
                    Parameter = "SSL",
                    Description = $"Could not establish TLS connection: {ex.Message}",
                    Remediation = "Ensure TLS 1.2+ is enabled and a valid certificate is installed.",
                    Module = "SslChecker",
                    Confidence = 100
                });
            }

            // Analyze certificate
            if (cert != null)
            {
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "Certificate Info",
                    Severity = "Info",
                    Url = $"https://{host}:443",
                    Parameter = "Certificate",
                    Description = $"Subject: {cert.Subject} | Issuer: {cert.Issuer} | Valid: {cert.NotBefore:yyyy-MM-dd} to {cert.NotAfter:yyyy-MM-dd}",
                    Remediation = "N/A",
                    Module = "SslChecker",
                    Confidence = 100
                });

                // Check certificate expiry
                var daysUntilExpiry = (cert.NotAfter - DateTime.Now).TotalDays;
                if (daysUntilExpiry < 0)
                {
                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = "Expired Certificate",
                        Severity = "Critical",
                        Url = $"https://{host}:443",
                        Parameter = "Certificate",
                        Description = $"Certificate expired on {cert.NotAfter:yyyy-MM-dd} ({Math.Abs(daysUntilExpiry):F0} days ago).",
                        Remediation = "Renew the SSL/TLS certificate immediately.",
                        Module = "SslChecker",
                        Confidence = 100
                    });
                }
                else if (daysUntilExpiry < 30)
                {
                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = "Certificate Expiring Soon",
                        Severity = "Medium",
                        Url = $"https://{host}:443",
                        Parameter = "Certificate",
                        Description = $"Certificate expires in {daysUntilExpiry:F0} days ({cert.NotAfter:yyyy-MM-dd}).",
                        Remediation = "Renew the certificate before it expires.",
                        Module = "SslChecker",
                        Confidence = 100
                    });
                }

                // Check for self-signed certificates
                if (cert.Subject == cert.Issuer)
                {
                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = "Self-Signed Certificate",
                        Severity = "Medium",
                        Url = $"https://{host}:443",
                        Parameter = "Certificate",
                        Description = "Server is using a self-signed certificate.",
                        Remediation = "Use a certificate from a trusted Certificate Authority (CA).",
                        Module = "SslChecker",
                        Confidence = 100
                    });
                }
            }

            // Check TLS protocol version
            if (negotiatedProtocol != SslProtocols.None)
            {
                var isWeakProtocol = negotiatedProtocol switch
                {
                    SslProtocols.Ssl2 or SslProtocols.Ssl3 => true,
                    SslProtocols.Tls or SslProtocols.Tls11 => true,
                    _ => false
                };

                if (isWeakProtocol)
                {
                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = "Weak TLS Protocol",
                        Severity = "High",
                        Url = $"https://{host}:443",
                        Parameter = "TLS Protocol",
                        Payload = negotiatedProtocol.ToString(),
                        Description = $"Server negotiated {negotiatedProtocol} which is considered insecure.",
                        Remediation = "Disable TLS 1.0/1.1 and SSL. Enable only TLS 1.2 and TLS 1.3.",
                        Module = "SslChecker",
                        Confidence = 100
                    });
                }
                else
                {
                    Logger.WriteLine($"  ✓ Protocol {negotiatedProtocol} is modern", ConsoleColor.Green);
                }
            }

            // Check HSTS header
            try
            {
                using var httpClient = new HttpClient(new HttpClientHandler
                {
                    ServerCertificateCustomValidationCallback = (_, _, _, _) => true
                });
                httpClient.Timeout = TimeSpan.FromSeconds(10);
                var response = await httpClient.GetAsync($"https://{host}/");
                result.RequestsSent++;

                if (response.Headers.Contains("Strict-Transport-Security"))
                {
                    var hsts = response.Headers.GetValues("Strict-Transport-Security").FirstOrDefault() ?? "";
                    Logger.WriteLine($"  ✓ HSTS header present", ConsoleColor.Green);
                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = "HSTS Header Present",
                        Severity = "Info",
                        Url = $"https://{host}",
                        Parameter = "Strict-Transport-Security",
                        Payload = hsts,
                        Description = $"HSTS header is set: {hsts}",
                        Remediation = "N/A",
                        Module = "SslChecker",
                        Confidence = 100
                    });
                }
                else
                {
                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = "Missing HSTS Header",
                        Severity = "Medium",
                        Url = $"https://{host}",
                        Parameter = "Strict-Transport-Security",
                        Description = "HSTS header is not set. Users may connect over insecure HTTP.",
                        Remediation = "Add Strict-Transport-Security header with max-age of at least 1 year and includeSubDomains.",
                        Module = "SslChecker",
                        Confidence = 100
                    });
                }
            }
            catch (Exception ex)
            {
                Logger.Debug($"HSTS check failed: {ex.Message}");
            }

            result.Completed = true;
        }
        catch (Exception ex)
        {
            result.ErrorMessage = ex.Message;
            Logger.Error($"SSL checker failed: {ex.Message}");
        }

        result.EndTime = DateTime.UtcNow;
        return result;
    }

    private static string ExtractHost(string url)
    {
        try
        {
            if (url.Contains("://"))
                return new Uri(url).Host;
            var colonIndex = url.LastIndexOf(':');
            return colonIndex > 0 && int.TryParse(url[(colonIndex + 1)..], out _) ? url[..colonIndex] : url;
        }
        catch { return url; }
    }
}
