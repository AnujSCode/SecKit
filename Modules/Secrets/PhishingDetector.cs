using System.Net;
using System.Text.RegularExpressions;
using SecKit.Core;
using SecKit.Models;

namespace SecKit.Modules.Secrets;

/// <summary>
/// Analyzes domain email security posture (SPF, DKIM, DMARC) and detects
/// typosquatting / homoglyph domains that could be used in phishing attacks.
/// </summary>
public class PhishingDetector
{
    private readonly ConfigManager _config;

    private readonly string[] _dkimSelectors;

    // Homoglyph mappings for typosquatting generation
    private static readonly Dictionary<char, char> Homoglyphs = new()
    {
        ['a'] = '\u0430', // Cyrillic а
        ['c'] = '\u0441', // Cyrillic с
        ['e'] = '\u0435', // Cyrillic е
        ['o'] = '\u043E', // Cyrillic о
        ['p'] = '\u0440', // Cyrillic р
        ['x'] = '\u0445', // Cyrillic х
        ['i'] = '\u0456', // Cyrillic і
        ['l'] = 'I',      // Capital I for lowercase l
        ['0'] = 'O',      // Capital O for zero
    };

    // Common TLDs for typosquatting check
    private static readonly string[] CommonTlds = { ".com", ".net", ".org", ".io", ".co", ".app", ".dev", ".ai", ".biz", ".info" };

    public PhishingDetector(ConfigManager config)
    {
        _config = config;
        _dkimSelectors = config.DkimSelectors.ToArray();
    }

    /// <summary>
    /// Scans a domain for email security configuration and typosquatting risks.
    /// </summary>
    /// <param name="target">A domain name (e.g., "example.com").</param>
    /// <returns>A <see cref="ScanResult"/> with phishing-related findings.</returns>
    public async Task<ScanResult> ScanAsync(string target)
    {
        var result = new ScanResult
        {
            ModuleName = "Phishing Detector",
            TargetUrl = target,
            StartTime = DateTime.UtcNow
        };

        try
        {
            var domain = ExtractDomain(target);
            Logger.Info($"Analyzing phishing posture for domain: {domain}");

            // ── Phase 1: Email Security Checks ──
            var spf = await CheckSpfAsync(domain, result);
            var dkim = await CheckDkimAsync(domain, result);
            var dmarc = await CheckDmarcAsync(domain, result);

            result.EndpointsTested = 3 + _dkimSelectors.Length; // SPF + DKIM probes + DMARC

            // ── Phase 2: Typosquatting Detection ──
            await CheckTyposquattingAsync(domain, result);

            // ── Phase 3: Summary assessment ──
            AssessEmailSecurity(result, domain, spf, dkim, dmarc);

            result.Completed = true;
        }
        catch (Exception ex)
        {
            result.ErrorMessage = ex.Message;
            Logger.Error($"Phishing detector failed: {ex.Message}");
        }

        result.EndTime = DateTime.UtcNow;
        return result;
    }

    // ─────────────────────────────────────────────
    //  Email Security Checks
    // ─────────────────────────────────────────────

    /// <summary>
    /// Checks for an SPF record via TXT DNS lookup.
    /// </summary>
    private static async Task<string> CheckSpfAsync(string domain, ScanResult result)
    {
        try
        {
            var records = await DnsLookupAsync(domain, "TXT");
            result.RequestsSent++;

            var spfRecord = records.FirstOrDefault(r => r.Contains("v=spf1", StringComparison.OrdinalIgnoreCase));

            if (spfRecord != null)
            {
                Logger.WriteLine($"  ✓ SPF record found", ConsoleColor.Green);
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "SPF Record Present",
                    Severity = "Info",
                    Url = domain,
                    Parameter = "SPF",
                    Payload = spfRecord,
                    Description = $"SPF record found: {spfRecord}",
                    Remediation = "Ensure SPF record ends with -all (hard fail) rather than ~all (soft fail) for strict enforcement.",
                    Module = "PhishingDetector",
                    Confidence = 100
                });

                // Check for soft-fail
                if (spfRecord.Contains("~all", StringComparison.OrdinalIgnoreCase))
                {
                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = "SPF: Soft-fail Policy (~all)",
                        Severity = "Medium",
                        Url = domain,
                        Parameter = "SPF",
                        Payload = spfRecord,
                        Description = "SPF record uses ~all (soft-fail). Spoofed emails may still be delivered.",
                        Remediation = "Change ~all to -all for hard-fail enforcement of SPF policy.",
                        Module = "PhishingDetector",
                        Confidence = 90
                    });
                }

                return "pass";
            }

            Logger.WriteLine($"  ✗ No SPF record found", ConsoleColor.Red);
            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "Missing SPF Record",
                Severity = "High",
                Url = domain,
                Parameter = "SPF",
                Description = "No SPF record found. Emails from this domain can be easily spoofed.",
                Remediation = "Add an SPF TXT record: 'v=spf1 mx -all' (or configure appropriate senders).",
                Module = "PhishingDetector",
                Confidence = 100
            });

            return "fail";
        }
        catch (Exception ex)
        {
            Logger.Debug($"SPF check error: {ex.Message}");

            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "SPF: Lookup Failed",
                Severity = "Medium",
                Url = domain,
                Parameter = "SPF",
                Description = $"Could not check SPF record: {ex.Message}",
                Remediation = "Ensure DNS is correctly configured and the domain is reachable.",
                Module = "PhishingDetector",
                Confidence = 80
            });

            return "not found";
        }
    }

    /// <summary>
    /// Checks for DKIM records by probing common selectors.
    /// </summary>
    private async Task<string> CheckDkimAsync(string domain, ScanResult result)
    {
        var foundSelectors = new List<string>();

        foreach (var selector in _dkimSelectors)
        {
            try
            {
                var dkimDomain = $"{selector}._domainkey.{domain}";
                var records = await DnsLookupAsync(dkimDomain, "TXT");
                result.RequestsSent++;

                var dkimRecord = records.FirstOrDefault(r =>
                    r.Contains("v=DKIM", StringComparison.OrdinalIgnoreCase) ||
                    r.Contains("k=rsa", StringComparison.OrdinalIgnoreCase));

                if (dkimRecord != null)
                {
                    foundSelectors.Add(selector);
                    Logger.Debug($"  DKIM found with selector: {selector}");
                }
            }
            catch
            {
                // Selector doesn't exist — expected for most
            }
        }

        if (foundSelectors.Count > 0)
        {
            Logger.WriteLine($"  ✓ DKIM configured ({foundSelectors.Count} selector(s): {string.Join(", ", foundSelectors)})", ConsoleColor.Green);

            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "DKIM: Configured",
                Severity = "Info",
                Url = domain,
                Parameter = "DKIM",
                Payload = string.Join(", ", foundSelectors),
                Description = $"DKIM is configured with selectors: {string.Join(", ", foundSelectors)}",
                Remediation = "Ensure DKIM keys are at least 2048 bits and rotate periodically.",
                Module = "PhishingDetector",
                Confidence = 100
            });

            return "pass";
        }

        Logger.WriteLine($"  ✗ No DKIM records found", ConsoleColor.Red);

        result.Vulnerabilities.Add(new Vulnerability
        {
            Type = "Missing DKIM Records",
            Severity = "High",
            Url = domain,
            Parameter = "DKIM",
            Description = "No DKIM records found for common selectors. Emails may lack cryptographic signatures, making them vulnerable to tampering.",
            Remediation = "Configure DKIM signing for your email provider and add the TXT record at selector._domainkey.yourdomain.com.",
            Module = "PhishingDetector",
            Confidence = 100
        });

        return "fail";
    }

    /// <summary>
    /// Checks for a DMARC TXT record.
    /// </summary>
    private static async Task<string> CheckDmarcAsync(string domain, ScanResult result)
    {
        try
        {
            var dmarcDomain = $"_dmarc.{domain}";
            var records = await DnsLookupAsync(dmarcDomain, "TXT");
            result.RequestsSent++;

            var dmarcRecord = records.FirstOrDefault(r =>
                r.Contains("v=DMARC", StringComparison.OrdinalIgnoreCase));

            if (dmarcRecord != null)
            {
                Logger.WriteLine($"  ✓ DMARC record found", ConsoleColor.Green);

                var policy = "none";
                if (dmarcRecord.Contains("p=reject", StringComparison.OrdinalIgnoreCase))
                    policy = "reject";
                else if (dmarcRecord.Contains("p=quarantine", StringComparison.OrdinalIgnoreCase))
                    policy = "quarantine";

                var severity = policy switch
                {
                    "reject" => "Info",
                    "quarantine" => "Low",
                    _ => "High"
                };

                var description = policy switch
                {
                    "reject" => "DMARC is configured with p=reject. Unauthorized emails are rejected.",
                    "quarantine" => "DMARC is configured with p=quarantine. Unauthorized emails are quarantined.",
                    _ => "DMARC is configured but with p=none (monitoring only). Spoofed emails are not blocked."
                };

                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = $"DMARC: Policy = {policy}",
                    Severity = severity,
                    Url = domain,
                    Parameter = "DMARC",
                    Payload = dmarcRecord,
                    Description = description,
                    Remediation = policy == "none"
                        ? "Gradually upgrade from p=none → p=quarantine → p=reject after confirming legitimate senders pass authentication."
                        : $"DMARC is properly configured with p={policy}.",
                    Module = "PhishingDetector",
                    Confidence = 100
                });

                if (policy == "none")
                    return "fail"; // Technically present but not enforcing

                return "pass";
            }

            Logger.WriteLine($"  ✗ No DMARC record found", ConsoleColor.Red);

            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "Missing DMARC Record",
                Severity = "High",
                Url = domain,
                Parameter = "DMARC",
                Description = "No DMARC record found. The domain has no policy for handling email authentication failures, leaving it vulnerable to spoofing.",
                Remediation = "Add a DMARC TXT record: '_dmarc.example.com TXT v=DMARC; p=none; rua=mailto:dmarc@example.com'. Start with p=none then escalate.",
                Module = "PhishingDetector",
                Confidence = 100
            });

            return "fail";
        }
        catch (Exception ex)
        {
            Logger.Debug($"DMARC check error: {ex.Message}");

            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "DMARC: Lookup Failed",
                Severity = "Medium",
                Url = domain,
                Parameter = "DMARC",
                Description = $"Could not check DMARC record: {ex.Message}",
                Remediation = "Ensure DNS is correctly configured and _dmarc TXT record is accessible.",
                Module = "PhishingDetector",
                Confidence = 80
            });

            return "not found";
        }
    }

    /// <summary>
    /// Provides a summary assessment of the domain's email security posture.
    /// </summary>
    private static void AssessEmailSecurity(ScanResult result, string domain, string spf, string dkim, string dmarc)
    {
        var passed = new List<string>();
        var failed = new List<string>();

        if (spf == "pass") passed.Add("SPF");
        else failed.Add("SPF");

        if (dkim == "pass") passed.Add("DKIM");
        else failed.Add("DKIM");

        if (dmarc == "pass") passed.Add("DMARC");
        else failed.Add("DMARC");

        if (failed.Count == 0)
        {
            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "Email Security: Fully Configured",
                Severity = "Info",
                Url = domain,
                Parameter = "Email Security",
                Description = $"All email security standards are properly configured: {string.Join(", ", passed)}.",
                Remediation = "Monitor DMARC reports and rotate DKIM keys periodically.",
                Module = "PhishingDetector",
                Confidence = 100
            });
        }
        else if (failed.Count == 3)
        {
            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "Email Security: Critical — No Protection",
                Severity = "Critical",
                Url = domain,
                Parameter = "Email Security",
                Description = "No email authentication configured. SPF, DKIM, and DMARC are all missing. This domain is highly vulnerable to email spoofing and phishing.",
                Remediation = "Implement SPF, DKIM, and DMARC immediately. Start with SPF, add DKIM, and configure DMARC with p=none.",
                Module = "PhishingDetector",
                Confidence = 100
            });
        }
        else
        {
            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "Email Security: Partial Protection",
                Severity = "High",
                Url = domain,
                Parameter = "Email Security",
                Description = $"Missing: {string.Join(", ", failed)}. Configured: {string.Join(", ", passed)}. Incomplete email authentication leaves gaps for phishing.",
                Remediation = $"Implement the missing standards: {string.Join(", ", failed)}.",
                Module = "PhishingDetector",
                Confidence = 100
            });
        }
    }

    // ─────────────────────────────────────────────
    //  Typosquatting / Homoglyph Detection
    // ─────────────────────────────────────────────

    /// <summary>
    /// Generates common typos and homoglyph variants of the target domain,
    /// then checks which ones resolve (indicating potential phishing domains).
    /// </summary>
    private async Task CheckTyposquattingAsync(string domain, ScanResult result)
    {
        Logger.Info("Checking for typosquatted domains...");

        // Extract base name (without TLD)
        var parts = domain.Split('.');
        if (parts.Length < 2)
        {
            Logger.Debug($"Domain '{domain}' doesn't have a TLD — skipping typosquatting check.");
            return;
        }

        var baseName = parts[0];
        var tld = "." + parts[^1];

        var candidates = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // ── Missing character typo ──
        for (int i = 0; i < baseName.Length; i++)
        {
            candidates.Add(baseName[..i] + baseName[(i + 1)..] + tld);
        }

        // ── Swapped adjacent characters ──
        for (int i = 0; i < baseName.Length - 1; i++)
        {
            var chars = baseName.ToCharArray();
            (chars[i], chars[i + 1]) = (chars[i + 1], chars[i]);
            candidates.Add(new string(chars) + tld);
        }

        // ── Extra character (double a character) ──
        for (int i = 0; i < baseName.Length; i++)
        {
            candidates.Add(baseName[..(i + 1)] + baseName[i] + baseName[(i + 1)..] + tld);
        }

        // ── Homoglyph substitution ──
        foreach (var (original, homoglyph) in Homoglyphs)
        {
            var lower = baseName.ToLowerInvariant();
            var indices = new List<int>();
            for (int i = 0; i < lower.Length; i++)
                if (lower[i] == original) indices.Add(i);

            if (indices.Count > 0)
            {
                var chars = baseName.ToCharArray();
                foreach (var idx in indices)
                {
                    chars[idx] = homoglyph;
                }
                candidates.Add(new string(chars) + tld);
            }
        }

        // ── Common TLD variants ──
        foreach (var altTld in CommonTlds)
        {
            if (!altTld.Equals(tld, StringComparison.OrdinalIgnoreCase))
                candidates.Add(baseName + altTld);
        }

        // ── Hyphen insertion ──
        var mid = baseName.Length / 2;
        if (mid > 0 && mid < baseName.Length)
            candidates.Add(baseName[..mid] + "-" + baseName[mid..] + tld);

        // ── Omit dot (e.g., googlecom.com) ──
        candidates.Add(baseName + tld.Replace(".", "") + tld);

        Logger.Debug($"Generated {candidates.Count} typosquatting candidates. Checking resolution...");

        var resolved = new List<(string Domain, bool HasHttps)>();

        foreach (var candidate in candidates)
        {
            if (candidate.Equals(domain, StringComparison.OrdinalIgnoreCase))
                continue; // Skip self

            try
            {
                var resolveResult = await TryResolveDomainAsync(candidate);
                result.RequestsSent++;

                if (resolveResult.resolved)
                {
                    resolved.Add((candidate, resolveResult.hasHttps));
                    Logger.WriteLine($"  ⚠ Typosquat found: {candidate} resolves", ConsoleColor.Yellow);
                }
            }
            catch
            {
                // Doesn't resolve — expected for most typos
            }

            // Rate limit — small delay to avoid overwhelming DNS
            if (result.RequestsSent % 20 == 0)
                await Task.Delay(100);
        }

        if (resolved.Count > 0)
        {
            Logger.WriteLine($"  ⚠ Found {resolved.Count} typosquatted domains that resolve!", ConsoleColor.Red);

            foreach (var (d, hasHttps) in resolved)
            {
                var severity = hasHttps ? "High" : "Medium";

                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "Typosquatted Domain Detected",
                    Severity = severity,
                    Url = d,
                    Parameter = "Typosquatting",
                    Payload = d,
                    Description = hasHttps
                        ? $"Typosquatted domain '{d}' resolves and has HTTPS. This is an active phishing threat."
                        : $"Typosquatted domain '{d}' resolves (no HTTPS detected). May be used for phishing.",
                    Evidence = $"Original domain: {domain}. Resolved variant: {d}",
                    Remediation = "Monitor these domains. Consider defensive registration or filing a UDRP/ACPA complaint if malicious.",
                    Module = "PhishingDetector",
                    Confidence = 75
                });
            }
        }
        else
        {
            Logger.WriteLine("  ✓ No typosquatted domains found resolving", ConsoleColor.Green);
        }
    }

    // ─────────────────────────────────────────────
    //  DNS / Resolution Helpers
    // ─────────────────────────────────────────────

    /// <summary>
    /// Performs a DNS TXT record lookup for the given domain.
    /// </summary>
    private static async Task<List<string>> DnsLookupAsync(string domain, string recordType)
    {
        // .NET DNS APIs don't have native TXT lookup via Dns.GetHostEntry.
        // We use a workaround: query the DNS via UDP directly parsing TXT records,
        // or fall back to Dns.GetHostAddresses as a resolution check.
        //
        // For cross-platform TXT record support, we use a lightweight DNS-over-UDP approach.
        try
        {
            // Try using Dns.GetHostEntry first to see if the domain resolves at all
            var entry = await System.Net.Dns.GetHostEntryAsync(domain);
            var ips = entry.AddressList;
            if (ips.Length == 0) return new List<string>();

            // Use a manual DNS TXT query via UDP to the system's DNS server
            return await QueryDnsTxtAsync(domain);
        }
        catch
        {
            return new List<string>();
        }
    }

    /// <summary>
    /// Sends a raw DNS TXT query via UDP and parses the response.
    /// Falls back gracefully on failure.
    /// </summary>
    private static async Task<List<string>> QueryDnsTxtAsync(string domain)
    {
        var results = new List<string>();

        try
        {
            // Use system DNS resolver via UDP to 8.8.8.8 (Google DNS) or system resolver
            var dnsServer = "8.8.8.8";
            var dnsPort = 53;

            using var udp = new System.Net.Sockets.UdpClient();
            udp.Client.ReceiveTimeout = 3000;
            udp.Client.SendTimeout = 3000;
            await udp.SendAsync(BuildDnsQuery(domain, 16 /* TXT */), dnsServer, dnsPort);

            var response = await udp.ReceiveAsync();
            results = ParseDnsTxtResponse(response.Buffer, domain);
        }
        catch
        {
            // Fallback: try nslookup/dig if available (unlikely in pure .NET)
            // For now, return empty list gracefully
        }

        return results;
    }

    /// <summary>
    /// Builds a minimal DNS query for a specific record type.
    /// </summary>
    private static byte[] BuildDnsQuery(string domain, ushort queryType)
    {
        using var ms = new System.IO.MemoryStream();
        // Transaction ID (random)
        var txId = (ushort)Random.Shared.Next(0, 65535);
        ms.WriteByte((byte)(txId >> 8));
        ms.WriteByte((byte)(txId & 0xFF));

        // Flags: standard query, recursion desired
        ms.Write(new byte[] { 0x01, 0x00 });

        // Questions: 1
        ms.Write(new byte[] { 0x00, 0x01 });

        // Answer, Authority, Additional: 0
        ms.Write(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });

        // Encode domain name as labels
        var labels = domain.Split('.');
        foreach (var label in labels)
        {
            if (label.Length > 63) throw new ArgumentException("Label too long");
            ms.WriteByte((byte)label.Length);
            foreach (var c in label)
                ms.WriteByte((byte)c);
        }
        ms.WriteByte(0); // Terminator

        // Query type (TXT = 16)
        ms.WriteByte((byte)(queryType >> 8));
        ms.WriteByte((byte)(queryType & 0xFF));

        // Query class (IN = 1)
        ms.WriteByte(0x00);
        ms.WriteByte(0x01);

        return ms.ToArray();
    }

    /// <summary>
    /// Parses TXT record data from a DNS response packet.
    /// </summary>
    private static List<string> ParseDnsTxtResponse(byte[] response, string domain)
    {
        var results = new List<string>();
        if (response.Length < 12) return results;

        // Skip header (12 bytes)
        var offset = 12;

        // Skip question section
        while (offset < response.Length && response[offset] != 0)
        {
            var len = response[offset];
            offset += len + 1;
        }
        offset++; // skip null terminator
        offset += 4; // skip QTYPE + QCLASS

        // Parse answer section
        while (offset < response.Length - 12)
        {
            // Skip name (may be compressed with pointer)
            if ((response[offset] & 0xC0) == 0xC0)
            {
                offset += 2; // pointer is 2 bytes
            }
            else
            {
                while (offset < response.Length && response[offset] != 0)
                    offset += response[offset] + 1;
                offset++; // null terminator
            }

            if (offset + 10 > response.Length) break;

            // Type (2 bytes), Class (2 bytes), TTL (4 bytes), RDLength (2 bytes)
            var rType = (response[offset] << 8) | response[offset + 1];
            offset += 2;
            var rClass = (response[offset] << 8) | response[offset + 1];
            offset += 2;
            offset += 4; // TTL
            var rdLength = (response[offset] << 8) | response[offset + 1];
            offset += 2;

            if (offset + rdLength > response.Length) break;

            // TXT record (type 16)
            if (rType == 16)
            {
                var txtData = offset;
                var sb = new System.Text.StringBuilder();
                while (txtData < offset + rdLength)
                {
                    var txtLen = response[txtData];
                    txtData++;
                    if (txtData + txtLen > offset + rdLength) break;
                    for (int i = 0; i < txtLen; i++)
                        sb.Append((char)response[txtData + i]);
                    txtData += txtLen;
                }
                results.Add(sb.ToString());
            }

            offset += rdLength;
        }

        return results;
    }

    /// <summary>
    /// Attempts to resolve a domain and check if it serves HTTPS.
    /// </summary>
    private static async Task<(bool resolved, bool hasHttps)> TryResolveDomainAsync(string domain)
    {
        try
        {
            var entry = await System.Net.Dns.GetHostEntryAsync(domain);
            if (entry.AddressList.Length == 0)
                return (false, false);

            // Try HTTPS connection to check if it serves TLS
            bool hasHttps = false;
            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                using var tcp = new System.Net.Sockets.TcpClient();
                await tcp.ConnectAsync(entry.AddressList[0], 443, cts.Token);
                hasHttps = true;
            }
            catch
            {
                // No HTTPS — still resolved though
            }

            return (true, hasHttps);
        }
        catch
        {
            return (false, false);
        }
    }

    /// <summary>
    /// Extracts a bare domain from a URL or domain string.
    /// </summary>
    private static string ExtractDomain(string input)
    {
        // Remove protocol if present
        var domain = Regex.Replace(input, @"^https?://", "", RegexOptions.IgnoreCase);
        // Remove path/query/fragment
        var slashIdx = domain.IndexOf('/');
        if (slashIdx > 0) domain = domain[..slashIdx];
        // Remove port
        var colonIdx = domain.LastIndexOf(':');
        if (colonIdx > 0) domain = domain[..colonIdx];
        // Lowercase
        return domain.ToLowerInvariant().Trim();
    }
}
