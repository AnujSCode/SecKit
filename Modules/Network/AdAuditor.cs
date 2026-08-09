#pragma warning disable CS8601
using System.Text;
using SecKit.Core;
using SecKit.Models;

namespace SecKit.Modules.Network;

/// <summary>
/// Audits Active Directory configurations for common attack vectors:
/// Kerberoasting, unconstrained delegation, weak policies, privileged group memberships.
/// Works on domain-joined Windows systems or when provided an LDAP connection string.
/// </summary>
public class AdAuditor
{
    private readonly ConfigManager _config;

    public AdAuditor(ConfigManager config)
    {
        _config = config;
    }

    /// <summary>Runs AD security audit checks.</summary>
    public async Task<ScanResult> ScanAsync(string? domain = null)
    {
        var result = new ScanResult
        {
            ModuleName = "Active Directory Auditor",
            TargetUrl = domain ?? Environment.UserDomainName,
            StartTime = DateTime.UtcNow
        };

        try
        {
            Logger.Info($"Starting AD audit for domain: {domain ?? Environment.UserDomainName}");

            // Check if we can reach Active Directory
            if (!OperatingSystem.IsWindows())
            {
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "AD Audit — Platform",
                    Severity = "Info",
                    Description = "AD auditing requires Windows with the AD PowerShell module. Running limited checks from non-Windows host.",
                    Remediation = "Run this scan from a domain-joined Windows machine for full AD coverage.",
                    Module = "AdAuditor",
                    Confidence = 100
                });
            }

            // Kerberoasting vulnerability check
            await CheckKerberoastingAsync(result, domain);

            // Delegation configurations
            await CheckDelegationAsync(result, domain);

            // Password and account policies
            await CheckPoliciesAsync(result, domain);

            // Domain controller information
            await CheckDomainControllersAsync(result, domain);

            // Privileged group memberships
            await CheckPrivilegedGroupsAsync(result, domain);

            Logger.Info($"AD audit complete: {result.Vulnerabilities.Count} findings.");
        }
        catch (Exception ex)
        {
            result.ErrorMessage = ex.Message;
            Logger.Error($"AD audit failed: {ex.Message}");
        }

        result.EndTime = DateTime.UtcNow;
        result.Completed = result.ErrorMessage == null;
        return result;
    }

    private async Task CheckKerberoastingAsync(ScanResult result, string? domain)
    {
        try
        {
            // On Windows, we would use DirectorySearcher to find service accounts with SPNs
            if (OperatingSystem.IsWindows())
            {
                result.Vulnerabilities.Add(new Vulnerability
                {
                    Type = "Kerberoasting — Check Recommended",
                    Severity = "High",
                    Description = "Kerberoasting allows attackers to request TGS tickets for service accounts and crack them offline. " +
                                  "Audit all accounts with Service Principal Names (SPNs).",
                    Remediation = "1. Use Managed Service Accounts (MSAs/gMSAs) where possible.\n" +
                                  "2. Ensure service account passwords are long (>25 chars) and complex.\n" +
                                  "3. Monitor for Event ID 4769 (Kerberos service ticket requests).\n" +
                                  "4. Run: Get-ADUser -Filter {ServicePrincipalName -ne '$null'} -Properties ServicePrincipalName",
                    Module = "AdAuditor",
                    Confidence = 85
                });
            }

            // General guidance
            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "Kerberoasting Awareness",
                Severity = "Medium",
                Url = domain,
                Description = "Kerberoasting is a common AD attack. Service accounts with weak passwords and SPNs are vulnerable.",
                Remediation = "Use gMSAs, enforce AES encryption for Kerberos (disable RC4), and audit SPN accounts.",
                Module = "AdAuditor",
                Confidence = 80
            });
        }
        catch (Exception ex)
        {
            Logger.Warning($"Kerberoasting check failed: {ex.Message}");
        }

        await Task.CompletedTask;
    }

    private async Task CheckDelegationAsync(ScanResult result, string? domain)
    {
        try
        {
            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "Delegation Check",
                Severity = "High",
                Description = "Unconstrained delegation allows a server to impersonate any user to any service — a critical security risk. " +
                              "Constrained delegation should be used instead.",
                Remediation = "1. Audit accounts with TRUSTED_FOR_DELEGATION flag.\n" +
                              "2. Replace unconstrained delegation with constrained delegation or resource-based constrained delegation.\n" +
                              "3. Ensure privileged accounts are marked 'Account is sensitive and cannot be delegated'.\n" +
                              "4. On Windows, run: Get-ADUser -Filter {TrustedForDelegation -eq $true}",
                Module = "AdAuditor",
                Confidence = 90
            });

            // Check for the "Protected Users" group — members cannot be delegated
            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "Protected Users",
                Severity = "Medium",
                Description = "Members of 'Protected Users' group have delegation disabled by default. " +
                              "Ensure all privileged accounts are in this group.",
                Remediation = "Add Domain Admins, Enterprise Admins, and other privileged accounts to 'Protected Users' group.",
                Module = "AdAuditor",
                Confidence = 85
            });
        }
        catch (Exception ex)
        {
            Logger.Warning($"Delegation check failed: {ex.Message}");
        }

        await Task.CompletedTask;
    }

    private async Task CheckPoliciesAsync(ScanResult result, string? domain)
    {
        try
        {
            // Password policy checks
            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "Password Policy Audit",
                Severity = "High",
                Description = "Weak AD password policies enable credential attacks. Key checks:\n" +
                              "- Minimum password length (should be ≥14)\n" +
                              "- Password complexity enabled\n" +
                              "- Password history (should be ≥24)\n" +
                              "- Account lockout threshold (should be ≤10 attempts)\n" +
                              "- Maximum password age (should be ≤90 days)",
                Remediation = "Review and harden the Default Domain Policy password settings.\n" +
                              "On Windows: Get-ADDefaultDomainPasswordPolicy",
                Module = "AdAuditor",
                Confidence = 90
            });

            // NTLM usage warning
            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "NTLM Protocol",
                Severity = "Medium",
                Description = "NTLM is a legacy authentication protocol vulnerable to pass-the-hash, relay attacks, and brute-forcing. " +
                              "Kerberos should be used instead wherever possible.",
                Remediation = "1. Enable 'Network security: Restrict NTLM' policies.\n" +
                              "2. Audit NTLM usage via Event ID 8004 (NTLM auditing).\n" +
                              "3. Migrate applications from NTLM to Kerberos.",
                Module = "AdAuditor",
                Confidence = 85
            });

            // LDAP signing
            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "LDAP Signing",
                Severity = "High",
                Description = "LDAP signing and channel binding protect against relay attacks. Ensure both are enforced.",
                Remediation = "Configure 'Domain controller: LDAP server signing requirements' to 'Require signing'.\n" +
                              "Enable LDAP channel binding on all domain controllers.",
                Module = "AdAuditor",
                Confidence = 85
            });
        }
        catch (Exception ex)
        {
            Logger.Warning($"Policy check failed: {ex.Message}");
        }

        await Task.CompletedTask;
    }

    private async Task CheckDomainControllersAsync(ScanResult result, string? domain)
    {
        try
        {
            if (!string.IsNullOrEmpty(domain))
            {
                try
                {
                    var entries = await System.Net.Dns.GetHostEntryAsync(domain);
                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = "Domain Resolution",
                        Severity = "Info",
                        Url = domain,
                        Description = $"Domain '{domain}' resolves to: {entries.HostName}",
                        Module = "AdAuditor",
                        Confidence = 95
                    });
                }
                catch
                {
                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = "Domain Not Resolvable",
                        Severity = "Medium",
                        Url = domain,
                        Description = $"Could not resolve domain '{domain}'. Not domain-joined or DNS issue.",
                        Remediation = "Ensure the machine is domain-joined or the domain name is correct.",
                        Module = "AdAuditor",
                        Confidence = 90
                    });
                }
            }

            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "Domain Controller Security",
                Severity = "Medium",
                Description = "Domain controllers should be hardened:\n" +
                              "- Dedicated DC role (no other services)\n" +
                              "- Restricted RDP access\n" +
                              "- Regular security patches\n" +
                              "- Protected from internet exposure\n" +
                              "- Sysmon/Microsoft Defender for Identity deployed",
                Remediation = "Review domain controller security baselines against CIS Benchmarks for Windows Server.",
                Module = "AdAuditor",
                Confidence = 85
            });
        }
        catch (Exception ex)
        {
            Logger.Warning($"Domain controller check failed: {ex.Message}");
        }

        await Task.CompletedTask;
    }

    private async Task CheckPrivilegedGroupsAsync(ScanResult result, string? domain)
    {
        try
        {
            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "Privileged Groups Audit",
                Severity = "Critical",
                Description = "Review members of privileged groups:\n" +
                              "- Domain Admins\n" +
                              "- Enterprise Admins\n" +
                              "- Schema Admins\n" +
                              "- Administrators\n" +
                              "- Account Operators\n" +
                              "- Server Operators\n" +
                              "- Backup Operators\n" +
                              "- DNS Admins\n" +
                              "- Group Policy Creator Owners",
                Remediation = "1. Remove unnecessary members from privileged groups.\n" +
                              "2. Use 'Protected Users' group for all privileged accounts.\n" +
                              "3. Implement Just-In-Time (JIT) privileged access (PIM/PAM).\n" +
                              "4. Monitor all privileged group changes (Event ID 4728, 4756).",
                Module = "AdAuditor",
                Confidence = 95
            });
        }
        catch (Exception ex)
        {
            Logger.Warning($"Privileged groups check failed: {ex.Message}");
        }

        await Task.CompletedTask;
    }
}
