using SecKit.Core;
using SecKit.Models;

namespace SecKit.Modules.CloudAudit;

/// <summary>
/// Scans AWS S3 buckets for security misconfigurations: public access,
/// bucket policies, ACLs, encryption settings, versioning, logging,
/// and overly permissive policies. Outputs info-level findings when AWS
/// credentials are not configured.
/// </summary>
public class S3BucketScanner
{
    private readonly ConfigManager _config;

    public S3BucketScanner(ConfigManager config)
    {
        _config = config;
    }

    /// <summary>Scans all accessible S3 buckets for security issues.</summary>
    public async Task<ScanResult> ScanAsync(string target = "aws")
    {
        var result = new ScanResult
        {
            ModuleName = "S3 Bucket Scanner",
            TargetUrl = target,
            StartTime = DateTime.UtcNow
        };

        try
        {
            // Check if AWS SDK is available and credentials are configured
            string? credsError = CheckAwsCredentials();
            if (credsError != null)
            {
                AddInfoVuln(result, "AWS Credentials Not Configured",
                    $"Cannot scan S3 buckets: {credsError}. Configure AWS credentials via environment variables, ~/.aws/credentials, or IAM role.",
                    "Set AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_REGION environment variables, or run `aws configure`.");
                result.Completed = true;
                result.EndTime = DateTime.UtcNow;
                return result;
            }

            // Use AWSSDK.S3 to enumerate buckets
            using var s3Client = new Amazon.S3.AmazonS3Client();

            var listResponse = await s3Client.ListBucketsAsync();
            result.RequestsSent++;

            var buckets = listResponse.Buckets;
            result.EndpointsTested = buckets.Count;

            Logger.Info($"Found {buckets.Count} S3 bucket(s).");

            foreach (var bucket in buckets)
            {
                Logger.Info($"  Auditing bucket: {bucket.BucketName}");

                // Check each security aspect
                await CheckPublicAccessBlockAsync(result, s3Client, bucket.BucketName);
                await CheckBucketPolicyAsync(result, s3Client, bucket.BucketName);
                await CheckEncryptionAsync(result, s3Client, bucket.BucketName);
                await CheckVersioningAsync(result, s3Client, bucket.BucketName);
                await CheckLoggingAsync(result, s3Client, bucket.BucketName);
                await CheckAclAsync(result, s3Client, bucket.BucketName);
            }

            result.Completed = true;
        }
        catch (Amazon.S3.AmazonS3Exception awsEx)
        {
            result.ErrorMessage = $"AWS S3 error: {awsEx.Message}";
            Logger.Error($"S3 Scanner AWS error: {awsEx.Message}");
        }
        catch (Exception ex)
        {
            result.ErrorMessage = ex.Message;
            Logger.Error($"S3 Bucket Scanner failed: {ex.Message}");
        }

        result.EndTime = DateTime.UtcNow;
        return result;
    }

    /// <summary>Checks the public access block configuration for a bucket.</summary>
    private async Task CheckPublicAccessBlockAsync(ScanResult result, Amazon.S3.AmazonS3Client client, string bucketName)
    {
        try
        {
            result.RequestsSent++;
            var response = await client.GetPublicAccessBlockAsync(new Amazon.S3.Model.GetPublicAccessBlockRequest { BucketName = bucketName });
            var config = response.PublicAccessBlockConfiguration;

            bool blockPublicAcls = config.BlockPublicAcls;
            bool ignorePublicAcls = config.IgnorePublicAcls;
            bool blockPublicPolicy = config.BlockPublicPolicy;
            bool restrictPublicBuckets = config.RestrictPublicBuckets;

            if (!blockPublicAcls || !blockPublicPolicy || !restrictPublicBuckets)
            {
                var issues = new List<string>();
                if (!blockPublicAcls) issues.Add("BlockPublicAcls is false");
                if (!ignorePublicAcls) issues.Add("IgnorePublicAcls is false");
                if (!blockPublicPolicy) issues.Add("BlockPublicPolicy is false");
                if (!restrictPublicBuckets) issues.Add("RestrictPublicBuckets is false");

                AddVuln(result, $"s3://{bucketName}", "S3: Weak Public Access Block",
                    $"Bucket '{bucketName}' has weak public access block settings: {string.Join(", ", issues)}",
                    "Critical", 90,
                    "Enable all four public access block settings: BlockPublicAcls=true, IgnorePublicAcls=true, BlockPublicPolicy=true, RestrictPublicBuckets=true.");
            }
        }
        catch (Amazon.S3.AmazonS3Exception ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            // No public access block configured — this is dangerous
            AddVuln(result, $"s3://{bucketName}", "S3: No Public Access Block",
                $"Bucket '{bucketName}' has no public access block configured. It can be made public at any time.",
                "High", 90,
                "Configure public access block with all four settings enabled.");
        }
        catch (Exception ex)
        {
            Logger.Debug($"Public access block check failed for {bucketName}: {ex.Message}");
        }
    }

    /// <summary>Checks the bucket policy for overly permissive statements.</summary>
    private async Task CheckBucketPolicyAsync(ScanResult result, Amazon.S3.AmazonS3Client client, string bucketName)
    {
        try
        {
            result.RequestsSent++;
            var response = await client.GetBucketPolicyAsync(bucketName);
            var policy = response.Policy;

            if (!string.IsNullOrWhiteSpace(policy))
            {
                // Check for overly permissive policies
                bool hasPrincipalWildcard = policy.Contains("\"Principal\":\"*\"") ||
                    policy.Contains("\"Principal\":{\"AWS\":\"*\"}") ||
                    policy.Contains("\"Principal\" : \"*\"");
                bool hasActionWildcard = policy.Contains("\"Action\":\"*\"") ||
                    policy.Contains("\"Action\":\"s3:*\"") ||
                    policy.Contains("\"Action\" : \"*\"");
                bool hasResourceWildcard = policy.Contains("\"Resource\":\"arn:aws:s3:::*\"") ||
                    policy.Contains("\"Resource\":\"*\"");

                if (hasPrincipalWildcard && (hasActionWildcard || hasResourceWildcard))
                {
                    AddVuln(result, $"s3://{bucketName}", "S3: Overly Permissive Policy",
                        $"Bucket '{bucketName}' has a policy with broad permissions (Principal=*, Action=all). This could allow public access.",
                        "Critical", 85,
                        "Restrict the Principal to specific AWS accounts or IAM roles. Limit Action to the minimum required S3 permissions.");
                }
                else if (hasPrincipalWildcard)
                {
                    AddVuln(result, $"s3://{bucketName}", "S3: Policy With Wildcard Principal",
                        $"Bucket '{bucketName}' policy uses Principal=*. Review whether public access is intended.",
                        "High", 70,
                        "If public access is not required, replace '*' with specific principals.");
                }
            }
        }
        catch (Amazon.S3.AmazonS3Exception ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            // No bucket policy — that's fine if ACLs are also restricted
        }
        catch (Exception ex)
        {
            Logger.Debug($"Bucket policy check failed for {bucketName}: {ex.Message}");
        }
    }

    /// <summary>Checks if default encryption is enabled on the bucket.</summary>
    private async Task CheckEncryptionAsync(ScanResult result, Amazon.S3.AmazonS3Client client, string bucketName)
    {
        try
        {
            result.RequestsSent++;
            var response = await client.GetBucketEncryptionAsync(new Amazon.S3.Model.GetBucketEncryptionRequest { BucketName = bucketName });

            var rules = response.ServerSideEncryptionConfiguration?.ServerSideEncryptionRules;
            if (rules == null || !rules.Any())
            {
                AddVuln(result, $"s3://{bucketName}", "S3: No Default Encryption",
                    $"Bucket '{bucketName}' has no default server-side encryption configured. Objects may be stored unencrypted.",
                    "High", 90,
                    "Enable default encryption: SSE-S3 (AES-256) or SSE-KMS for managed key encryption.");
            }
        }
        catch (Amazon.S3.AmazonS3Exception ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            AddVuln(result, $"s3://{bucketName}", "S3: No Encryption Configured",
                $"Bucket '{bucketName}' has no encryption configuration.",
                "High", 95,
                "Enable SSE-S3 or SSE-KMS default encryption on the bucket.");
        }
        catch (Exception ex)
        {
            Logger.Debug($"Encryption check failed for {bucketName}: {ex.Message}");
        }
    }

    /// <summary>Checks if versioning is enabled on the bucket.</summary>
    private async Task CheckVersioningAsync(ScanResult result, Amazon.S3.AmazonS3Client client, string bucketName)
    {
        try
        {
            result.RequestsSent++;
            var response = await client.GetBucketVersioningAsync(bucketName);

            if (response.VersioningConfig?.Status != Amazon.S3.VersionStatus.Enabled)
            {
                AddVuln(result, $"s3://{bucketName}", "S3: Versioning Not Enabled",
                    $"Bucket '{bucketName}' does not have versioning enabled. Accidental or malicious deletions are permanent.",
                    "Medium", 80,
                    "Enable S3 versioning to protect against accidental and malicious object deletion.");
            }

            // Check MFA delete
            if (response.VersioningConfig?.EnableMfaDelete == true)
            {
                Logger.Debug($"Bucket {bucketName} has MFA Delete enabled (good).");
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"Versioning check failed for {bucketName}: {ex.Message}");
        }
    }

    /// <summary>Checks if server access logging is enabled on the bucket.</summary>
    private async Task CheckLoggingAsync(ScanResult result, Amazon.S3.AmazonS3Client client, string bucketName)
    {
        try
        {
            result.RequestsSent++;
            var response = await client.GetBucketLoggingAsync(bucketName);

            if (response.BucketLoggingConfig == null || response.BucketLoggingConfig.LoggingEnabled == null)
            {
                AddVuln(result, $"s3://{bucketName}", "S3: Logging Not Enabled",
                    $"Bucket '{bucketName}' does not have server access logging enabled. Requests to the bucket are not logged.",
                    "Low", 60,
                    "Enable S3 server access logging to a dedicated logging bucket for audit and forensics.");
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"Logging check failed for {bucketName}: {ex.Message}");
        }
    }

    /// <summary>Checks the bucket ACL for public access grants.</summary>
    private async Task CheckAclAsync(ScanResult result, Amazon.S3.AmazonS3Client client, string bucketName)
    {
        try
        {
            result.RequestsSent++;
            var response = await client.GetACLAsync(bucketName);

            foreach (var grant in response.AccessControlList?.Grants ?? new List<Amazon.S3.Model.S3Grant>())
            {
                var grantee = grant.Grantee;
                var permission = grant.Permission;

                // Check for public grants
                if (grantee?.URI != null &&
                    (grantee.URI.Contains("AllUsers", StringComparison.OrdinalIgnoreCase) ||
                     grantee.URI.Contains("AuthenticatedUsers", StringComparison.OrdinalIgnoreCase)))
                {
                    var audience = grantee.URI.Contains("AllUsers") ? "everyone" : "all AWS users";
                    AddVuln(result, $"s3://{bucketName}", "S3: Public ACL Grant",
                        $"Bucket '{bucketName}' grants {permission} access to {audience} via ACL.",
                        permission.Value.Contains("WRITE") || permission.Value.Contains("FULL") ? "Critical" : "High", 95,
                        "Remove public ACL grants. Use IAM policies and bucket policies instead. Enable all public access block settings.");
                }
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"ACL check failed for {bucketName}: {ex.Message}");
        }
    }

    // --- Helpers ---

    private static string? CheckAwsCredentials()
    {
        // Check common credential sources
        if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("AWS_ACCESS_KEY_ID")) &&
            !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("AWS_SECRET_ACCESS_KEY")))
            return null;

        // Check ~/.aws/credentials
        var credsPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".aws", "credentials");
        if (File.Exists(credsPath))
            return null;

        // Check SSO / config
        var configPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".aws", "config");
        if (File.Exists(configPath))
            return null;

        // Check if running on EC2/ECS with IAM role
        try
        {
            var metadataUrl = Environment.GetEnvironmentVariable("ECS_CONTAINER_METADATA_URI_V4");
            if (!string.IsNullOrEmpty(metadataUrl))
                return null;
        }
        catch { }

        return "No AWS credentials found. Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables, or configure ~/.aws/credentials.";
    }

    private void AddVuln(ScanResult result, string url, string type, string description,
        string severity, int confidence, string remediation)
    {
        var vuln = new Vulnerability
        {
            Type = type,
            Severity = severity,
            Url = url,
            Parameter = "S3 Bucket",
            Payload = "",
            Description = description,
            Evidence = "",
            Remediation = remediation,
            Module = "S3BucketScanner",
            Confidence = confidence
        };
        result.Vulnerabilities.Add(vuln);
        Logger.LogVulnerability(vuln);
    }

    private void AddInfoVuln(ScanResult result, string type, string description, string remediation)
    {
        var vuln = new Vulnerability
        {
            Type = type,
            Severity = "Info",
            Url = "N/A",
            Parameter = "Configuration",
            Payload = "",
            Description = description,
            Remediation = remediation,
            Module = "S3BucketScanner",
            Confidence = 100
        };
        result.Vulnerabilities.Add(vuln);
        Logger.LogVulnerability(vuln);
    }
}
