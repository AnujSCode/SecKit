using System.Text;
using System.Text.Json;
using SecKit.Core;
using SecKit.Models;

namespace SecKit.Modules.AiSecurityTester;

/// <summary>Tests AI/LLM endpoints for prompt injection using canary tokens. Payloads from config.</summary>
public class PromptInjectionTester
{
    private readonly HttpClient _client;
    private readonly ConfigManager _config;
    private readonly (string Payload, string Category, string Severity, string Canary)[] _injections;

    public PromptInjectionTester(HttpClient client, ConfigManager config)
    {
        _client = client;
        _config = config;
        _injections = config.PromptInjections
            .Select(p => (p.Payload, p.Category, p.Severity, p.Canary)).ToArray();
    }

    public async Task<ScanResult> TestAsync(string targetUrl)
    {
        var result = new ScanResult { ModuleName = "Prompt Injection Tester", TargetUrl = targetUrl, StartTime = DateTime.UtcNow };
        try
        {
            result.EndpointsTested = 1;
            Logger.Info($"Testing AI endpoint {targetUrl} for prompt injection...");

            foreach (var (payload, category, severity, canary) in _injections)
            {
                try
                {
                    result.RequestsSent++;
                    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
                    var responseText = await SendAsync(targetUrl, payload, cts.Token);
                    if (responseText is null) continue;

                    if (IsInjected(responseText, payload, canary))
                    {
                        result.Vulnerabilities.Add(new Vulnerability
                        {
                            Type = $"Prompt Injection - {category}", Severity = severity, Url = targetUrl,
                            Parameter = "prompt", Payload = Truncate(payload, 120),
                            Evidence = $"Model emitted canary token '{canary}'",
                            Description = $"The endpoint followed an injected instruction ({category}) and emitted the canary token '{canary}'.",
                            Remediation = "Separate system instructions from user input, apply input/output filtering, constrain tool access, and add an injection-detection guardrail.",
                            Module = "PromptInjectionTester", Confidence = severity == "Critical" ? 85 : 70
                        });
                    }
                }
                catch (TaskCanceledException) { Logger.Debug($"Prompt injection timeout for {category}"); }
                catch (Exception ex) { Logger.Debug($"Prompt injection test error: {ex.Message}"); }
            }
            result.Completed = true;
        }
        catch (Exception ex) { result.ErrorMessage = ex.Message; Logger.Error($"Prompt injection tester failed: {ex.Message}"); }
        result.EndTime = DateTime.UtcNow;
        return result;
    }

    private static bool IsInjected(string response, string payload, string canary)
    {
        if (!response.Contains(canary, StringComparison.OrdinalIgnoreCase)) return false;
        var probe = payload.Length > 40 ? payload[..40] : payload;
        if (response.Contains(probe, StringComparison.OrdinalIgnoreCase)) return false;
        return true;
    }

    private async Task<string?> SendAsync(string endpoint, string payload, CancellationToken ct)
    {
        var requestBody = new { messages = new[] { new { role = "user", content = payload } } };
        var json = JsonSerializer.Serialize(requestBody);
        var content = new StringContent(json, Encoding.UTF8, "application/json");
        var response = await _client.PostAsync(endpoint, content, ct);
        if (!response.IsSuccessStatusCode) return null;
        return await response.Content.ReadAsStringAsync(ct);
    }

    private static string Truncate(string value, int maxLength) => value.Length > maxLength ? value[..maxLength] + "..." : value;
}
