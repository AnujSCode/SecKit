#pragma warning disable CS8602
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecKit.Core;
using SecKit.Models;

namespace SecKit.Modules.RedTeam;

/// <summary>
/// Audits GraphQL endpoints for common vulnerabilities: introspection disclosure,
/// batching attacks, deep query DoS via nested fragments, circular fragment detection,
/// and sensitive field exposure in the schema.
/// </summary>
public class GraphQLAuditor
{
    private readonly HttpClient _client;
    private readonly ConfigManager _config;

    private static readonly string[] GraphQLEndpoints =
    {
        "/graphql", "/api/graphql", "/gql", "/graphiql",
        "/api/gql", "/v1/graphql", "/query", "/graph",
        "/playground", "/api", "/graphql/console",
    };

    // Full introspection query for schema discovery
    private const string IntrospectionQuery = @"
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args { ...InputValue }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args { ...InputValue }
    type { ...TypeRef }
    isDeprecated
    deprecationReason
  }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes { ...TypeRef }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
      }
    }
  }
}";

    // Sensitive field name patterns
    private static readonly string[] SensitiveFieldPatterns =
    {
        "password", "secret", "token", "key", "credential",
        "ssn", "socialSecurity", "creditCard", "cvv", "cvc",
        "apiKey", "privateKey", "accessToken", "refreshToken",
        "sessionId", "authToken", "jwt", "pin", "passcode",
        "securityQuestion", "securityAnswer", "mfaSecret",
        "otpSecret", "recoveryCode", "backupCode"
    };

    public GraphQLAuditor(HttpClient client, ConfigManager config)
    {
        _client = client;
        _config = config;
    }

    /// <summary>Scans a target for GraphQL endpoints and audits for vulnerabilities.</summary>
    public async Task<ScanResult> ScanAsync(string target)
    {
        var result = new ScanResult
        {
            ModuleName = "GraphQL Auditor",
            TargetUrl = target,
            StartTime = DateTime.UtcNow
        };

        try
        {
            // Phase 1: Discover GraphQL endpoints
            var endpoints = await DiscoverEndpointsAsync(result, target);

            if (endpoints.Count == 0)
            {
                Logger.Info("No GraphQL endpoints discovered on target.");
                result.Completed = true;
                result.EndTime = DateTime.UtcNow;
                return result;
            }

            result.EndpointsTested = endpoints.Count;
            Logger.Info($"Found {endpoints.Count} GraphQL endpoint(s) on target.");

            foreach (var endpoint in endpoints)
            {
                // Phase 2: Test introspection
                var schema = await TestIntrospectionAsync(result, endpoint);

                // Phase 3: If introspection works, check for sensitive fields
                if (schema != null)
                {
                    CheckSensitiveFields(result, endpoint, schema);
                    CheckCircularFragments(result, endpoint, schema);
                }

                // Phase 4: Test batching attacks
                await TestBatchingAsync(result, endpoint);

                // Phase 5: Test deep query DoS
                await TestDeepQueryDosAsync(result, endpoint);
            }

            result.Completed = true;
        }
        catch (Exception ex)
        {
            result.ErrorMessage = ex.Message;
            Logger.Error($"GraphQL Auditor failed: {ex.Message}");
        }

        result.EndTime = DateTime.UtcNow;
        return result;
    }

    private async Task<List<string>> DiscoverEndpointsAsync(ScanResult result, string target)
    {
        var endpoints = new List<string>();

        foreach (var path in GraphQLEndpoints)
        {
            try
            {
                result.RequestsSent++;
                var url = new Uri(new Uri(target), path).ToString();
                var response = await _client.GetAsync(url);
                var body = await response.Content.ReadAsStringAsync();

                // Check for GraphQL indicators
                var indicators = new[]
                {
                    "\"data\"", "graphql", "playground", "graphiql",
                    "__schema", "__type"
                };

                if (indicators.Any(i => body.Contains(i, StringComparison.OrdinalIgnoreCase)) &&
                    (response.IsSuccessStatusCode || response.StatusCode == System.Net.HttpStatusCode.BadRequest))
                {
                    endpoints.Add(url);
                    Logger.Info($"Discovered GraphQL at {url}");
                }
            }
            catch (Exception ex)
            {
                Logger.Debug($"GraphQL discovery failed for {path}: {ex.Message}");
            }
        }

        return endpoints;
    }

    private async Task<string?> TestIntrospectionAsync(ScanResult result, string endpoint)
    {
        try
        {
            result.RequestsSent++;
            var content = new StringContent(
                JsonSerializer.Serialize(new { query = IntrospectionQuery }),
                Encoding.UTF8, "application/json");

            var response = await _client.PostAsync(endpoint, content);
            var body = await response.Content.ReadAsStringAsync();

            // Check if introspection succeeded
            if (body.Contains("\"__schema\"") && body.Contains("\"types\""))
            {
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "GraphQL: Introspection Enabled",
                    Severity = "High",
                    Url = endpoint,
                    Parameter = "introspection query",
                    Payload = "Standard introspection query",
                    Description = "GraphQL introspection is enabled — attackers can discover the full API schema including hidden or internal types and fields.",
                    Evidence = $"Schema discovered; response size: {body.Length} bytes",
                    Remediation = "Disable introspection in production. For Apollo: ApolloServer({ introspection: false }). For GraphQL.NET: EnableMetrics = false.",
                    Module = "GraphQLAuditor",
                    Confidence = 100
                });
                Logger.LogVulnerability(result.Vulnerabilities.Last());

                return body;
            }
            else
            {
                Logger.Debug($"Introspection blocked at {endpoint}");
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"Introspection test failed for {endpoint}: {ex.Message}");
        }

        return null;
    }

    private void CheckSensitiveFields(ScanResult result, string endpoint, string schema)
    {
        try
        {
            foreach (var pattern in SensitiveFieldPatterns)
            {
                if (schema.Contains($"\"{pattern}\"", StringComparison.OrdinalIgnoreCase))
                {
                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = "GraphQL: Sensitive Field Exposed",
                        Severity = "High",
                        Url = endpoint,
                        Parameter = "schema field",
                        Payload = pattern,
                        Description = $"GraphQL schema exposes sensitive field '{pattern}'. This could leak credentials, tokens, or PII.",
                        Evidence = $"Field '{pattern}' found in introspection schema",
                        Remediation = $"Remove '{pattern}' from the GraphQL schema or apply field-level authorization. Consider using DTOs that exclude sensitive data.",
                        Module = "GraphQLAuditor",
                        Confidence = 85
                    });
                    Logger.LogVulnerability(result.Vulnerabilities.Last());
                }
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"Sensitive fields check failed: {ex.Message}");
        }
    }

    private void CheckCircularFragments(ScanResult result, string endpoint, string schema)
    {
        try
        {
            // Parse the schema to find types that reference themselves
            var doc = JsonNode.Parse(schema);
            var types = doc?["data"]?["__schema"]?["types"]?.AsArray();

            if (types == null) return;

            var typeDeps = new Dictionary<string, HashSet<string>>();

            foreach (var type in types)
            {
                var typeName = type?["name"]?.GetValue<string>();
                if (typeName == null || typeName.StartsWith("__")) continue;

                var fields = type["fields"]?.AsArray();
                if (fields == null) continue;

                var referencedTypes = new HashSet<string>();
                foreach (var field in fields)
                {
                    var typeRef = field?["type"];
                    CollectTypeNames(typeRef, referencedTypes);
                }

                if (referencedTypes.Contains(typeName))
                {
                    typeDeps[typeName] = referencedTypes;
                }
            }

            if (typeDeps.Count > 0)
            {
                var circularTypes = string.Join(", ", typeDeps.Keys.Take(5));
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "GraphQL: Circular Type References",
                    Severity = "Medium",
                    Url = endpoint,
                    Parameter = "schema types",
                    Payload = circularTypes,
                    Description = $"GraphQL schema has circular type references: {circularTypes}. Attackers can craft deeply nested queries to cause denial of service.",
                    Evidence = $"{typeDeps.Count} circular type(s) found in schema",
                    Remediation = "Implement query depth limiting and query cost analysis. Add a maximum depth limit (e.g., 5-10 levels). Use rate limiting on GraphQL endpoints.",
                    Module = "GraphQLAuditor",
                    Confidence = 80
                });
                Logger.LogVulnerability(result.Vulnerabilities.Last());
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"Circular fragment check failed: {ex.Message}");
        }
    }

    private void CollectTypeNames(JsonNode? typeRef, HashSet<string> collected)
    {
        if (typeRef == null) return;

        var name = typeRef["name"]?.GetValue<string>();
        if (name != null) collected.Add(name);

        var ofType = typeRef["ofType"];
        if (ofType != null)
            CollectTypeNames(ofType, collected);
    }

    private async Task TestBatchingAsync(ScanResult result, string endpoint)
    {
        try
        {
            // Send multiple queries in a single JSON array (batching attack)
            var batchedQuery = new[]
            {
                new { query = "{ __typename }" },
                new { query = "{ __schema { queryType { name } } }" },
                new { query = "{ __type(name: \"Query\") { name } }" },
            };

            result.RequestsSent++;
            var content = new StringContent(
                JsonSerializer.Serialize(batchedQuery),
                Encoding.UTF8, "application/json");

            var response = await _client.PostAsync(endpoint, content);
            var body = await response.Content.ReadAsStringAsync();

            // Check if batching is supported (returns an array)
            if (body.TrimStart().StartsWith("[") && body.Contains("\"data\""))
            {
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "GraphQL: Query Batching Enabled",
                    Severity = "Medium",
                    Url = endpoint,
                    Parameter = "batch query",
                    Payload = "3 queries batched in single request",
                    Description = "GraphQL endpoint accepts batched queries. Attackers can bypass rate limits by sending multiple queries in one request.",
                    Evidence = $"Batched response received: {body.Length} bytes",
                    Remediation = "Disable query batching in production. For Apollo: disable the batch HTTP link.",
                    Module = "GraphQLAuditor",
                    Confidence = 90
                });
                Logger.LogVulnerability(result.Vulnerabilities.Last());
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"Batching test failed: {ex.Message}");
        }
    }

    private async Task TestDeepQueryDosAsync(ScanResult result, string endpoint)
    {
        try
        {
            // Craft a deeply nested query that could cause resource exhaustion
            var deepQuery = BuildDeepQuery(10); // 10 levels deep

            result.RequestsSent++;
            var content = new StringContent(
                JsonSerializer.Serialize(new { query = deepQuery }),
                Encoding.UTF8, "application/json");

            var startTime = DateTime.UtcNow;
            var response = await _client.PostAsync(endpoint, content);
            var elapsed = DateTime.UtcNow - startTime;

            if (elapsed.TotalSeconds > 3)
            {
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "GraphQL: Deep Query DoS Susceptible",
                    Severity = "High",
                    Url = endpoint,
                    Parameter = "deep query",
                    Payload = "10-level nested query",
                    Description = $"A deeply nested query took {elapsed.TotalSeconds:F1}s to process. The server is vulnerable to resource exhaustion via deep queries.",
                    Evidence = $"Response time: {elapsed.TotalMilliseconds}ms",
                    Remediation = "Implement query depth limiting (max 5-7 levels). Add query cost/complexity analysis. Set timeout limits on resolver execution.",
                    Module = "GraphQLAuditor",
                    Confidence = 75
                });
                Logger.LogVulnerability(result.Vulnerabilities.Last());
            }
            else if (elapsed.TotalSeconds > 0.5)
            {
                // Check if the server returned an error (which means it has some protection)
                var body = await response.Content.ReadAsStringAsync();
                if (!body.Contains("error") && !body.Contains("too deep"))
                {
                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = "GraphQL: Potential Query Depth Issue",
                        Severity = "Low",
                        Url = endpoint,
                        Parameter = "deep query",
                        Payload = "10-level nested query",
                        Description = $"Server processed a deeply nested query in {elapsed.TotalMilliseconds}ms. May be susceptible under higher load.",
                        Evidence = $"Response time: {elapsed.TotalMilliseconds}ms",
                        Remediation = "Implement query depth limiting as a preventive measure.",
                        Module = "GraphQLAuditor",
                        Confidence = 40
                    });
                    Logger.LogVulnerability(result.Vulnerabilities.Last());
                }
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"Deep query DoS test failed: {ex.Message}");
        }
    }

    /// <summary>Builds a deeply nested GraphQL query for DoS testing.</summary>
    private static string BuildDeepQuery(int depth)
    {
        var sb = new StringBuilder();
        sb.Append("query {");
        for (int i = 0; i < depth; i++)
        {
            sb.Append($" level{i}: __typename ");
            if (i < depth - 1)
                sb.Append("{");
        }
        sb.Append(new string('}', depth));
        sb.Append("}");
        return sb.ToString();
    }
}
