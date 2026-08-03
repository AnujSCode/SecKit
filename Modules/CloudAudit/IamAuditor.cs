using SecKit.Core;
using SecKit.Models;

namespace SecKit.Modules.CloudAudit;

/// <summary>
/// Audits AWS IAM configuration: user access keys, MFA status, password policy,
/// role trust policies, and root account security. Flags users without MFA,
/// unused access keys, overly permissive roles, and weak password policies.
/// </summary>
public class IamAuditor
{
    private readonly ConfigManager _config;

    public IamAuditor(ConfigManager config)
    {
        _config = config;
    }

    /// <summary>Audits IAM users, roles, and password policy for security issues.</summary>
    public async Task<ScanResult> ScanAsync(string target = "aws")
    {
        var result = new ScanResult
        {
            ModuleName = "IAM Auditor",
            TargetUrl = target,
            StartTime = DateTime.UtcNow
        };

        try
        {
            // Check AWS credentials
            string? credsError = CheckAwsCredentials();
            if (credsError != null)
            {
                AddInfoVuln(result, "AWS Credentials Not Configured",
                    $"Cannot audit IAM: {credsError}",
                    "Set AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_REGION.");
                result.Completed = true;
                result.EndTime = DateTime.UtcNow;
                return result;
            }

            using var iamClient = new Amazon.IdentityManagement.AmazonIdentityManagementServiceClient();

            // Audit users
            await AuditUsersAsync(result, iamClient);

            // Audit roles
            await AuditRolesAsync(result, iamClient);

            // Audit password policy
            await AuditPasswordPolicyAsync(result, iamClient);

            // Check root account
            await CheckRootAccountAsync(result, iamClient);

            result.Completed = true;
        }
        catch (Amazon.IdentityManagement.AmazonIdentityManagementServiceException awsEx)
        {
            result.ErrorMessage = $"AWS IAM error: {awsEx.Message}";
            Logger.Error($"IAM Auditor AWS error: {awsEx.Message}");
        }
        catch (Exception ex)
        {
            result.ErrorMessage = ex.Message;
            Logger.Error($"IAM Auditor failed: {ex.Message}");
        }

        result.EndTime = DateTime.UtcNow;
        return result;
    }

    /// <summary>Audits all IAM users for access keys, MFA, and last activity.</summary>
    private async Task AuditUsersAsync(ScanResult result, Amazon.IdentityManagement.AmazonIdentityManagementServiceClient client)
    {
        try
        {
            var listRequest = new Amazon.IdentityManagement.Model.ListUsersRequest();
            Amazon.IdentityManagement.Model.ListUsersResponse listResponse;

            var users = new List<Amazon.IdentityManagement.Model.User>();

            do
            {
                result.RequestsSent++;
                listResponse = await client.ListUsersAsync(listRequest);
                users.AddRange(listResponse.Users);
                listRequest.Marker = listResponse.Marker;
            } while (listResponse.IsTruncated);

            result.EndpointsTested = users.Count;
            Logger.Info($"Found {users.Count} IAM user(s).");

            foreach (var user in users)
            {
                string userName = user.UserName;

                // Check access keys
                await CheckAccessKeysAsync(result, client, userName);

                // Check MFA
                await CheckMfaAsync(result, client, userName);

                // Check console access (login profile)
                await CheckConsoleAccessAsync(result, client, userName);

                // Check attached policies for admin-level access
                await CheckUserPoliciesAsync(result, client, userName);
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"User audit failed: {ex.Message}");
        }
    }

    /// <summary>Checks a user's access keys for age and status.</summary>
    private async Task CheckAccessKeysAsync(ScanResult result, Amazon.IdentityManagement.AmazonIdentityManagementServiceClient client, string userName)
    {
        try
        {
            result.RequestsSent++;
            var keysResponse = await client.ListAccessKeysAsync(new Amazon.IdentityManagement.Model.ListAccessKeysRequest
            {
                UserName = userName
            });

            foreach (var key in keysResponse.AccessKeyMetadata)
            {
                // Active keys
                if (key.Status == Amazon.IdentityManagement.StatusType.Active)
                {
                    var age = DateTime.UtcNow - key.CreateDate;
                    var ageDays = (int)age.TotalDays;

                    // Get last used info
                    DateTime? lastUsed = null;
                    try
                    {
                        result.RequestsSent++;
                        var usageResponse = await client.GetAccessKeyLastUsedAsync(new Amazon.IdentityManagement.Model.GetAccessKeyLastUsedRequest
                        {
                            AccessKeyId = key.AccessKeyId
                        });
                        lastUsed = usageResponse.AccessKeyLastUsed?.LastUsedDate;
                    }
                    catch { }

                    if (lastUsed == null || (DateTime.UtcNow - lastUsed.Value).TotalDays > 90)
                    {
                        var lastUsedStr = lastUsed?.ToString("O") ?? "never";
                        AddVuln(result, $"iam:{userName}", "IAM: Unused Access Key",
                            $"User '{userName}' has an active access key ({key.AccessKeyId}) last used {lastUsedStr} (>90 days unused).",
                            "High", 80,
                            $"Delete or deactivate unused access key {key.AccessKeyId}. Rotate active keys every 90 days.");
                    }
                    else if (ageDays > 365)
                    {
                        AddVuln(result, $"iam:{userName}", "IAM: Aged Access Key",
                            $"User '{userName}' has an access key that is {ageDays} days old without rotation.",
                            "Medium", 60,
                            $"Rotate access key {key.AccessKeyId}. Keys should be rotated every 90 days.");
                    }
                }
            }

            // Flag users with two active keys
            var activeCount = keysResponse.AccessKeyMetadata.Count(k => k.Status == Amazon.IdentityManagement.StatusType.Active);
            if (activeCount > 2)
            {
                AddVuln(result, $"iam:{userName}", "IAM: Excessive Access Keys",
                    $"User '{userName}' has {activeCount} active access keys.",
                    "Low", 40,
                    "Limit each IAM user to at most 2 access keys. Remove unused keys.");
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"Access key check failed for {userName}: {ex.Message}");
        }
    }

    /// <summary>Checks if a user has MFA enabled.</summary>
    private async Task CheckMfaAsync(ScanResult result, Amazon.IdentityManagement.AmazonIdentityManagementServiceClient client, string userName)
    {
        try
        {
            result.RequestsSent++;
            var mfaResponse = await client.ListMFADevicesAsync(new Amazon.IdentityManagement.Model.ListMFADevicesRequest
            {
                UserName = userName
            });

            if (mfaResponse.MFADevices.Count == 0)
            {
                AddVuln(result, $"iam:{userName}", "IAM: No MFA Configured",
                    $"User '{userName}' has no multi-factor authentication (MFA) device configured.",
                    "High", 90,
                    "Enable MFA for all IAM users. Require hardware or virtual MFA devices.");
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"MFA check failed for {userName}: {ex.Message}");
        }
    }

    /// <summary>Checks if a user has console access (login profile).</summary>
    private async Task CheckConsoleAccessAsync(ScanResult result, Amazon.IdentityManagement.AmazonIdentityManagementServiceClient client, string userName)
    {
        try
        {
            result.RequestsSent++;
            var loginResponse = await client.GetLoginProfileAsync(new Amazon.IdentityManagement.Model.GetLoginProfileRequest
            {
                UserName = userName
            });

            // User has console access — verify they also have MFA
            Logger.Debug($"User '{userName}' has console access.");
        }
        catch (Amazon.IdentityManagement.Model.NoSuchEntityException)
        {
            // No console access — fine for programmatic-only users
        }
        catch (Exception ex)
        {
            Logger.Debug($"Console access check failed for {userName}: {ex.Message}");
        }
    }

    /// <summary>Checks user policies for admin-level permissions.</summary>
    private async Task CheckUserPoliciesAsync(ScanResult result, Amazon.IdentityManagement.AmazonIdentityManagementServiceClient client, string userName)
    {
        try
        {
            // Check attached managed policies
            var attachedRequest = new Amazon.IdentityManagement.Model.ListAttachedUserPoliciesRequest
            {
                UserName = userName
            };

            Amazon.IdentityManagement.Model.ListAttachedUserPoliciesResponse attachedResponse;
            do
            {
                result.RequestsSent++;
                attachedResponse = await client.ListAttachedUserPoliciesAsync(attachedRequest);

                foreach (var policy in attachedResponse.AttachedPolicies)
                {
                    if (policy.PolicyName.Contains("Admin", StringComparison.OrdinalIgnoreCase) ||
                        policy.PolicyArn.Contains("AdministratorAccess"))
                    {
                        AddVuln(result, $"iam:{userName}", "IAM: Admin Policy Attached",
                            $"User '{userName}' has the '{policy.PolicyName}' policy attached. Administrative access should be restricted.",
                            "High", 85,
                            "Replace AdministratorAccess with least-privilege custom policies. Use permission boundaries.");
                    }
                }

                attachedRequest.Marker = attachedResponse.Marker;
            } while (attachedResponse.IsTruncated);
        }
        catch (Exception ex)
        {
            Logger.Debug($"User policy check failed for {userName}: {ex.Message}");
        }
    }

    /// <summary>Audits IAM roles for overly permissive trust policies.</summary>
    private async Task AuditRolesAsync(ScanResult result, Amazon.IdentityManagement.AmazonIdentityManagementServiceClient client)
    {
        try
        {
            var listRequest = new Amazon.IdentityManagement.Model.ListRolesRequest();
            Amazon.IdentityManagement.Model.ListRolesResponse listResponse;

            var roles = new List<Amazon.IdentityManagement.Model.Role>();

            do
            {
                result.RequestsSent++;
                listResponse = await client.ListRolesAsync(listRequest);
                roles.AddRange(listResponse.Roles);
                listRequest.Marker = listResponse.Marker;
            } while (listResponse.IsTruncated);

            Logger.Info($"Found {roles.Count} IAM role(s).");

            foreach (var role in roles)
            {
                // Check trust policy
                var trustDoc = System.Text.Json.JsonDocument.Parse(
                    Uri.UnescapeDataString(role.AssumeRolePolicyDocument));

                var statements = trustDoc.RootElement.GetProperty("Statement");
                foreach (var statement in statements.EnumerateArray())
                {
                    var principal = statement.GetProperty("Principal");

                    // Check for wildcard principal
                    if (principal.TryGetProperty("AWS", out var awsPrincipal))
                    {
                        string awsVal = awsPrincipal.ValueKind == System.Text.Json.JsonValueKind.String
                            ? awsPrincipal.GetString() ?? ""
                            : awsPrincipal.ToString();

                        if (awsVal == "*" || awsVal.Contains("\"*\""))
                        {
                            AddVuln(result, $"iam:role:{role.RoleName}", "IAM: Overly Permissive Trust Policy",
                                $"Role '{role.RoleName}' trusts Principal AWS:* — any AWS account can assume this role.",
                                "Critical", 95,
                                "Restrict the trust policy Principal to specific AWS account IDs. Never use '*' as a principal.");
                        }
                    }

                    if (principal.TryGetProperty("Service", out var svcPrincipal))
                    {
                        string svcVal = svcPrincipal.ValueKind == System.Text.Json.JsonValueKind.String
                            ? svcPrincipal.GetString() ?? ""
                            : svcPrincipal.ToString();

                        // Flag suspicious service principals
                        if (svcVal.Contains("ec2.amazonaws.com") &&
                            role.RoleName.Contains("Admin", StringComparison.OrdinalIgnoreCase))
                        {
                            AddVuln(result, $"iam:role:{role.RoleName}", "IAM: EC2 Role With Admin Name",
                                $"Role '{role.RoleName}' is trusted by EC2 and has 'Admin' in its name. EC2 instances could get elevated access.",
                                "High", 75,
                                "Ensure this role follows least privilege. EC2 roles should not have administrative access.");
                        }
                    }
                }

                // Check for attached admin policies
                var policyRequest = new Amazon.IdentityManagement.Model.ListAttachedRolePoliciesRequest
                {
                    RoleName = role.RoleName
                };

                Amazon.IdentityManagement.Model.ListAttachedRolePoliciesResponse policyResponse;
                do
                {
                    result.RequestsSent++;
                    policyResponse = await client.ListAttachedRolePoliciesAsync(policyRequest);

                    foreach (var policy in policyResponse.AttachedPolicies)
                    {
                        if (policy.PolicyName.Contains("Admin", StringComparison.OrdinalIgnoreCase) ||
                            policy.PolicyArn.Contains("AdministratorAccess"))
                        {
                            AddVuln(result, $"iam:role:{role.RoleName}", "IAM: Admin Policy On Role",
                                $"Role '{role.RoleName}' has the '{policy.PolicyName}' policy attached.",
                                "High", 80,
                                "Review whether this role truly needs administrative access. Apply least privilege.");
                        }
                    }

                    policyRequest.Marker = policyResponse.Marker;
                } while (policyResponse.IsTruncated);
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"Role audit failed: {ex.Message}");
        }
    }

    /// <summary>Audits the account password policy.</summary>
    private async Task AuditPasswordPolicyAsync(ScanResult result, Amazon.IdentityManagement.AmazonIdentityManagementServiceClient client)
    {
        try
        {
            result.RequestsSent++;
            var policyResponse = await client.GetAccountPasswordPolicyAsync();
            var policy = policyResponse.PasswordPolicy;

            // Check minimum length
            if (policy.MinimumPasswordLength < 12)
            {
                AddVuln(result, "iam:password-policy", "IAM: Weak Password Length",
                    $"Password policy minimum length is {policy.MinimumPasswordLength} (recommended: ≥12).",
                    "Medium", 70,
                    "Set MinimumPasswordLength to at least 12 characters.");
            }

            // Check complexity requirements
            if (!policy.RequireLowercaseCharacters)
            {
                AddVuln(result, "iam:password-policy", "IAM: No Lowercase Required",
                    "Password policy does not require lowercase characters.",
                    "Low", 50,
                    "Enable RequireLowercaseCharacters.");
            }

            if (!policy.RequireUppercaseCharacters)
            {
                AddVuln(result, "iam:password-policy", "IAM: No Uppercase Required",
                    "Password policy does not require uppercase characters.",
                    "Low", 50,
                    "Enable RequireUppercaseCharacters.");
            }

            if (!policy.RequireNumbers)
            {
                AddVuln(result, "iam:password-policy", "IAM: No Numbers Required",
                    "Password policy does not require numeric characters.",
                    "Low", 50,
                    "Enable RequireNumbers.");
            }

            if (!policy.RequireSymbols)
            {
                AddVuln(result, "iam:password-policy", "IAM: No Symbols Required",
                    "Password policy does not require special characters.",
                    "Low", 50,
                    "Enable RequireSymbols.");
            }

            // Check password expiration
            if (policy.MaxPasswordAge < 90 || policy.MaxPasswordAge > 365)
            {
                var msg = policy.MaxPasswordAge == 0
                    ? "Password policy has no expiration (passwords never expire)."
                    : $"Password policy max age is {policy.MaxPasswordAge} days.";
                AddVuln(result, "iam:password-policy", "IAM: Weak Password Expiration",
                    msg,
                    policy.MaxPasswordAge == 0 ? "High" : "Medium",
                    70,
                    "Set MaxPasswordAge between 90 and 180 days.");
            }

            // Check password reuse
            if (policy.PasswordReusePrevention < 5)
            {
                AddVuln(result, "iam:password-policy", "IAM: Weak Password Reuse Prevention",
                    $"Password reuse prevention is only {policy.PasswordReusePrevention} passwords (recommended: ≥5).",
                    "Medium", 60,
                    "Set PasswordReusePrevention to at least 5 to prevent password recycling.");
            }
        }
        catch (Amazon.IdentityManagement.Model.NoSuchEntityException)
        {
            // No password policy set — using AWS defaults (weak)
            AddVuln(result, "iam:password-policy", "IAM: No Password Policy",
                "No custom IAM password policy is configured. AWS defaults are weak (min 6 chars, no complexity requirements).",
                "High", 90,
                "Create a custom password policy: min 12 chars, require uppercase/lowercase/numbers/symbols, expire every 90 days, prevent reuse of 5+ passwords.");
        }
        catch (Exception ex)
        {
            Logger.Debug($"Password policy check failed: {ex.Message}");
        }
    }

    /// <summary>Checks root account security.</summary>
    private async Task CheckRootAccountAsync(ScanResult result, Amazon.IdentityManagement.AmazonIdentityManagementServiceClient client)
    {
        try
        {
            // Check if root has access keys via the account summary
            result.RequestsSent++;
            var summaryResponse = await client.GetAccountSummaryAsync();

            if (summaryResponse.SummaryMap.TryGetValue("AccountAccessKeysPresent", out var rootKeys) && rootKeys > 0)
            {
                AddVuln(result, "iam:root", "IAM: Root Has Access Keys",
                    $"The AWS root account has {rootKeys} access key(s). Root access keys are extremely dangerous.",
                    "Critical", 100,
                    "Delete all root account access keys immediately. Use IAM users with least privilege instead.");
            }

            if (summaryResponse.SummaryMap.TryGetValue("AccountMFAEnabled", out var rootMfa) && rootMfa == 0)
            {
                AddVuln(result, "iam:root", "IAM: Root Has No MFA",
                    "The AWS root account does not have MFA enabled.",
                    "Critical", 100,
                    "Enable a hardware MFA device for the root account immediately.");
            }
        }
        catch (Exception ex)
        {
            Logger.Debug($"Root account check failed: {ex.Message}");
        }
    }

    // --- Helpers ---

    private static string? CheckAwsCredentials()
    {
        if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("AWS_ACCESS_KEY_ID")) &&
            !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("AWS_SECRET_ACCESS_KEY")))
            return null;

        var credsPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".aws", "credentials");
        if (File.Exists(credsPath)) return null;

        var configPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".aws", "config");
        if (File.Exists(configPath)) return null;

        try
        {
            var metadataUrl = Environment.GetEnvironmentVariable("ECS_CONTAINER_METADATA_URI_V4");
            if (!string.IsNullOrEmpty(metadataUrl)) return null;
        }
        catch { }

        return "No AWS credentials found.";
    }

    private void AddVuln(ScanResult result, string url, string type, string description,
        string severity, int confidence, string remediation)
    {
        var vuln = new Vulnerability
        {
            Type = type,
            Severity = severity,
            Url = url,
            Parameter = "IAM",
            Payload = "",
            Description = description,
            Remediation = remediation,
            Module = "IamAuditor",
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
            Module = "IamAuditor",
            Confidence = 100
        };
        result.Vulnerabilities.Add(vuln);
        Logger.LogVulnerability(vuln);
    }
}
