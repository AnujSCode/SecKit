#pragma warning disable CS1998
using System.Text;
using SecKit.Core;
using SecKit.Models;

namespace SecKit.Modules.Analysis;

/// <summary>
/// Generates copy-paste ready remediation commands for discovered vulnerabilities.
/// Groups fixes by category (network, web server, application, database, cloud, auth),
/// providing concrete CLI commands, config snippets, and code changes.
/// </summary>
public class RemediationEngine
{
    private readonly ConfigManager _config;

    // Category grouping
    private static readonly Dictionary<string, string[]> CategoryGroups = new()
    {
        ["Network & Firewall"] = new[] { "Port", "Firewall", "SSH", "RDP", "Security Group", "Open Port" },
        ["Web Server Config"] = new[] { "Header", "CORS", "CSP", "HSTS", "X-Frame", "SSL", "TLS" },
        ["Application Code"] = new[] { "SQL", "XSS", "CSRF", "SSRF", "Path Traversal", "File Upload", "IDOR" },
        ["Authentication"] = new[] { "JWT", "Auth", "Credential", "Password", "MFA", "Session", "IAM:", "Root" },
        ["Database"] = new[] { "MySQL", "PostgreSQL", "MongoDB", "Redis", "Memcached" },
        ["Cloud & S3"] = new[] { "S3:", "IAM:", "Cloud", "Bucket" },
        ["GraphQL & API"] = new[] { "GraphQL", "API", "Introspection", "Batching" },
        ["General"] = new[] { "Versioning", "Logging", "Encryption", "Unused" },
    };

    public RemediationEngine(ConfigManager config)
    {
        _config = config;
    }

    /// <summary>
    /// Generates ready-to-use remediation commands for a list of vulnerabilities,
    /// grouped by category with copy-paste ready shell commands and config snippets.
    /// </summary>
    /// <param name="vulnerabilities">The vulnerabilities to generate remediations for.</param>
    /// <returns>A scan result with remediation commands organized by category.</returns>
    public async Task<ScanResult> ScanAsync(List<Vulnerability> vulnerabilities)
    {
        var result = new ScanResult
        {
            ModuleName = "Remediation Engine",
            TargetUrl = "remediation",
            StartTime = DateTime.UtcNow
        };

        try
        {
            if (vulnerabilities.Count == 0)
            {
                Logger.Info("No vulnerabilities to remediate.");
                result.Completed = true;
                result.EndTime = DateTime.UtcNow;
                return result;
            }

            Logger.Info($"Generating remediation plan for {vulnerabilities.Count} vulnerabilities...");

            // Group vulnerabilities by category
            var grouped = GroupByCategory(vulnerabilities);

            // Generate remediation commands for each group
            foreach (var (category, vulns) in grouped)
            {
                var commands = GenerateRemediationCommands(category, vulns);
                if (commands.Count > 0)
                {
                    var sb = new StringBuilder();
                    sb.AppendLine($"=== {category.ToUpper()} REMEDIATION ===");
                    sb.AppendLine($"Affected: {vulns.Count} finding(s)");
                    sb.AppendLine();

                    foreach (var cmd in commands)
                    {
                        sb.AppendLine($"# {cmd.Description}");
                        sb.AppendLine(cmd.Command);
                        sb.AppendLine();
                    }

                    result.Vulnerabilities.Add(new Vulnerability
                    {
                        Type = $"Remediation: {category}",
                        Severity = "Info",
                        Url = "N/A",
                        Parameter = "Remediation",
                        Payload = $"{commands.Count} commands",
                        Description = sb.ToString(),
                        Evidence = $"Category: {category}, {vulns.Count} vulns",
                        Remediation = "Execute the commands above in order. Test in staging first.",
                        Module = "RemediationEngine",
                        Confidence = 100
                    });
                }
            }

            // Summary
            var summary = BuildSummary(vulnerabilities);
            result.Vulnerabilities.Add(new Vulnerability
            {
                Type = "Remediation Summary",
                Severity = "Info",
                Url = "N/A",
                Parameter = "Summary",
                Payload = summary,
                Description = summary,
                Evidence = $"Total: {vulnerabilities.Count} findings",
                Remediation = "Work through categories in priority order: Network → Auth → Application → Cloud.",
                Module = "RemediationEngine",
                Confidence = 100
            });

            result.RequestsSent = vulnerabilities.Count;
            result.EndpointsTested = 1;
            result.Completed = true;
        }
        catch (Exception ex)
        {
            result.ErrorMessage = ex.Message;
            Logger.Error($"Remediation Engine failed: {ex.Message}");
        }

        result.EndTime = DateTime.UtcNow;
        return result;
    }

    /// <summary>
    /// Groups vulnerabilities into remediation categories based on type and module.
    /// </summary>
    private Dictionary<string, List<Vulnerability>> GroupByCategory(List<Vulnerability> vulns)
    {
        var grouped = new Dictionary<string, List<Vulnerability>>();

        foreach (var vuln in vulns)
        {
            var category = Categorize(vuln);
            if (!grouped.ContainsKey(category))
                grouped[category] = new List<Vulnerability>();
            grouped[category].Add(vuln);
        }

        return grouped;
    }

    private static string Categorize(Vulnerability vuln)
    {
        foreach (var (category, keywords) in CategoryGroups)
        {
            foreach (var keyword in keywords)
            {
                if (vuln.Type.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                    vuln.Description.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                    vuln.Module.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                {
                    return category;
                }
            }
        }
        return "General";
    }

    /// <summary>
    /// Generates copy-paste ready remediation commands for a category of vulnerabilities.
    /// </summary>
    private List<(string Description, string Command)> GenerateRemediationCommands(
        string category, List<Vulnerability> vulns)
    {
        var commands = new List<(string Description, string Command)>();

        switch (category)
        {
            case "Network & Firewall":
                GenerateNetworkRemediations(commands, vulns);
                break;
            case "Web Server Config":
                GenerateWebServerRemediations(commands, vulns);
                break;
            case "Application Code":
                GenerateApplicationRemediations(commands, vulns);
                break;
            case "Authentication":
                GenerateAuthRemediations(commands, vulns);
                break;
            case "Database":
                GenerateDatabaseRemediations(commands, vulns);
                break;
            case "Cloud & S3":
                GenerateCloudRemediations(commands, vulns);
                break;
            case "GraphQL & API":
                GenerateGraphQLRemediations(commands, vulns);
                break;
            default:
                GenerateGeneralRemediations(commands, vulns);
                break;
        }

        return commands;
    }

    // --- Category-specific remediation generators ---

    private static void GenerateNetworkRemediations(List<(string, string)> commands, List<Vulnerability> vulns)
    {
        var hasOpenPorts = vulns.Any(v => v.Type.Contains("Open Port"));
        var hasBroadSg = vulns.Any(v => v.Type.Contains("Open to World"));
        var hasAllTraffic = vulns.Any(v => v.Type.Contains("All Traffic Open"));

        if (hasAllTraffic)
        {
            commands.Add(("Remove all-traffic rules from security groups",
                "# AWS: Remove all-traffic rule (REPLACE sg-xxx with actual SG ID)\n" +
                "aws ec2 revoke-security-group-ingress --group-id sg-xxx --protocol -1 --cidr 0.0.0.0/0"));
        }

        if (hasOpenPorts)
        {
            commands.Add(("Block SSH from public internet",
                "# Linux (iptables): Allow SSH only from trusted IP\n" +
                "iptables -A INPUT -p tcp --dport 22 -s 0.0.0.0/0 -j DROP\n" +
                "iptables -A INPUT -p tcp --dport 22 -s YOUR_TRUSTED_IP -j ACCEPT\n" +
                "\n" +
                "# Or change SSH to non-standard port in /etc/ssh/sshd_config:\n" +
                "# Port 2222\n" +
                "systemctl restart sshd"));

            commands.Add(("Block RDP from public internet",
                "# AWS Security Group CLI (REPLACE sg-xxx with actual SG ID):\n" +
                "aws ec2 revoke-security-group-ingress --group-id sg-xxx --protocol tcp --port 3389 --cidr 0.0.0.0/0\n" +
                "\n" +
                "# Linux (iptables):\n" +
                "iptables -A INPUT -p tcp --dport 3389 -j DROP"));

            commands.Add(("Close sensitive database ports",
                "# AWS: Remove MySQL/PostgreSQL/Redis/MongoDB public access\n" +
                "aws ec2 revoke-security-group-ingress --group-id sg-xxx --protocol tcp --port 3306 --cidr 0.0.0.0/0\n" +
                "aws ec2 revoke-security-group-ingress --group-id sg-xxx --protocol tcp --port 5432 --cidr 0.0.0.0/0\n" +
                "aws ec2 revoke-security-group-ingress --group-id sg-xxx --protocol tcp --port 6379 --cidr 0.0.0.0/0\n" +
                "aws ec2 revoke-security-group-ingress --group-id sg-xxx --protocol tcp --port 27017 --cidr 0.0.0.0/0"));
        }

        if (hasBroadSg)
        {
            commands.Add(("Audit and tighten all security group rules",
                "# List all security groups with their rules:\n" +
                "aws ec2 describe-security-groups --query 'SecurityGroups[*].{Name:GroupName,ID:GroupId,Rules:IpPermissions}' \\\n" +
                "  --output table\n" +
                "\n" +
                "# Restrict SSH access to specific IP:\n" +
                "aws ec2 authorize-security-group-ingress --group-id sg-xxx \\\n" +
                "  --protocol tcp --port 22 --cidr YOUR_IP/32"));
        }

        // Always add best practices
        commands.Add(("Install and configure fail2ban for brute force protection",
            "apt-get update && apt-get install -y fail2ban\n" +
            "cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local\n" +
            "# Edit /etc/fail2ban/jail.local and set:\n" +
            "# [sshd]\n" +
            "# enabled = true\n" +
            "# maxretry = 3\n" +
            "# bantime = 3600\n" +
            "systemctl enable fail2ban && systemctl start fail2ban"));

        commands.Add(("Enable and configure UFW (iptables wrapper)",
            "apt-get install -y ufw\n" +
            "ufw default deny incoming\n" +
            "ufw default allow outgoing\n" +
            "ufw allow 80/tcp\n" +
            "ufw allow 443/tcp\n" +
            "ufw allow from YOUR_TRUSTED_IP to any port 22 proto tcp\n" +
            "ufw --force enable\n" +
            "ufw status verbose"));
    }

    private static void GenerateWebServerRemediations(List<(string, string)> commands, List<Vulnerability> vulns)
    {
        var hasCorsIssues = vulns.Any(v => v.Type.Contains("CORS"));
        var hasHeaders = vulns.Any(v => v.Type.Contains("Header"));
        var hasSsl = vulns.Any(v => v.Type.Contains("SSL") || v.Type.Contains("TLS"));

        commands.Add(("Add security headers to nginx",
            "# Add to nginx server block in /etc/nginx/sites-available/default:\n" +
            "add_header X-Frame-Options \"DENY\" always;\n" +
            "add_header X-Content-Type-Options \"nosniff\" always;\n" +
            "add_header X-XSS-Protection \"1; mode=block\" always;\n" +
            "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n" +
            "add_header Permissions-Policy \"geolocation=(), microphone=(), camera=()\" always;\n" +
            "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n" +
            "\n" +
            "# Then reload:\n" +
            "nginx -t && systemctl reload nginx"));

        commands.Add(("Add security headers to Apache",
            "# Add to /etc/apache2/sites-available/000-default.conf or .htaccess:\n" +
            "Header always set X-Frame-Options \"DENY\"\n" +
            "Header always set X-Content-Type-Options \"nosniff\"\n" +
            "Header always set X-XSS-Protection \"1; mode=block\"\n" +
            "Header always set Referrer-Policy \"strict-origin-when-cross-origin\"\n" +
            "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"\n" +
            "\n" +
            "# Then reload:\n" +
            "a2enmod headers && systemctl reload apache2"));

        if (hasCorsIssues)
        {
            commands.Add(("Fix CORS to use specific origins in nginx",
                "# In nginx server block — allow only specific origins:\n" +
                "set $cors_origin \"\";\n" +
                "if ($http_origin ~* \"^https://(www\\.)?yourdomain\\.com$\") {\n" +
                "    set $cors_origin $http_origin;\n" +
                "}\n" +
                "add_header Access-Control-Allow-Origin $cors_origin;\n" +
                "add_header Access-Control-Allow-Methods \"GET, POST, OPTIONS\";\n" +
                "add_header Access-Control-Allow-Headers \"Authorization, Content-Type\";\n" +
                "add_header Access-Control-Allow-Credentials \"true\";\n" +
                "\n" +
                "# IMPORTANT: Never set ACAO to * when using credentials"));

            commands.Add(("Fix CORS in Express.js (Node.js)",
                "# Install and configure cors middleware:\n" +
                "npm install cors\n" +
                "\n" +
                "// In your Express app:\n" +
                "const cors = require('cors');\n" +
                "app.use(cors({\n" +
                "  origin: ['https://yourdomain.com'],\n" +
                "  methods: ['GET', 'POST'],\n" +
                "  allowedHeaders: ['Content-Type', 'Authorization'],\n" +
                "  credentials: true\n" +
                "}));"));
        }

        if (hasSsl)
        {
            commands.Add(("Enable strong TLS configuration in nginx",
                "# In nginx server block:\n" +
                "ssl_protocols TLSv1.2 TLSv1.3;\n" +
                "ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;\n" +
                "ssl_prefer_server_ciphers on;\n" +
                "ssl_session_cache shared:SSL:10m;\n" +
                "ssl_session_timeout 10m;\n" +
                "ssl_dhparam /etc/nginx/dhparam.pem;\n" +
                "\n" +
                "# Generate DH parameters (one-time):\n" +
                "openssl dhparam -out /etc/nginx/dhparam.pem 2048\n" +
                "\n" +
                "# Then reload:\n" +
                "nginx -t && systemctl reload nginx"));

            commands.Add(("Use Let's Encrypt for free TLS certificates",
                "apt-get install -y certbot python3-certbot-nginx\n" +
                "certbot --nginx -d yourdomain.com -d www.yourdomain.com\n" +
                "# Auto-renewal is set up automatically.\n" +
                "# Test renewal: certbot renew --dry-run"));
        }

        if (hasHeaders)
        {
            commands.Add(("Add Content-Security-Policy header (strict, customize as needed)",
                "# Nginx:\n" +
                "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'\" always;\n" +
                "\n" +
                "# Apache:\n" +
                "Header always set Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'\""));
        }
    }

    private static void GenerateApplicationRemediations(List<(string, string)> commands, List<Vulnerability> vulns)
    {
        var hasSqli = vulns.Any(v => v.Type.Contains("SQL Injection"));
        var hasXss = vulns.Any(v => v.Type.Contains("XSS"));
        var hasFileUpload = vulns.Any(v => v.Type.Contains("File Upload"));
        var hasPathTraversal = vulns.Any(v => v.Type.Contains("Path Traversal"));

        if (hasSqli)
        {
            commands.Add(("Fix SQL Injection: Use parameterized queries (C# / .NET example)",
                "// INSTEAD OF:\n" +
                "// string query = \"SELECT * FROM users WHERE name = '\" + input + \"'\";\n" +
                "\n" +
                "// USE parameterized queries:\n" +
                "using (var cmd = new SqlCommand(\"SELECT * FROM users WHERE name = @name\", connection))\n" +
                "{\n" +
                "    cmd.Parameters.AddWithValue(\"@name\", input);\n" +
                "    using (var reader = cmd.ExecuteReader()) { ... }\n" +
                "}\n" +
                "\n" +
                "// OR use an ORM like Entity Framework Core:\n" +
                "var user = await dbContext.Users.Where(u => u.Name == input).FirstOrDefaultAsync();"));

            commands.Add(("Fix SQL Injection: Parameterized queries (Node.js)",
                "// MySQL (bad):\n" +
                "// connection.query(\"SELECT * FROM users WHERE name = '\" + input + \"'\", ...)\n" +
                "\n" +
                "// MySQL (good - parameterized):\n" +
                "connection.query(\"SELECT * FROM users WHERE name = ?\", [input], callback)\n" +
                "\n" +
                "// PostgreSQL (good - parameterized):\n" +
                "pool.query(\"SELECT * FROM users WHERE name = $1\", [input], callback)\n" +
                "\n" +
                "// OR use an ORM:\n" +
                "// Prisma: prisma.user.findMany({ where: { name: input } })\n" +
                "// Sequelize: User.findAll({ where: { name: input } })"));
        }

        if (hasXss)
        {
            commands.Add(("Fix XSS: Context-aware output encoding (C#/Razor)",
                "// In Razor views — the @ syntax auto-encodes HTML:\n" +
                "// <p>@userInput</p>  -- auto-encoded\n" +
                "\n" +
                "// For JavaScript context:\n" +
                "// Use HttpUtility.JavaScriptStringEncode()\n" +
                "// <script>var name = '@HttpUtility.JavaScriptStringEncode(userInput)';</script>\n" +
                "\n" +
                "// For attribute context:\n" +
                "// <div data-value=\"@HttpUtility.HtmlAttributeEncode(userInput)\"></div>\n" +
                "\n" +
                "// Install HtmlSanitizer for rich text:\n" +
                "// dotnet add package HtmlSanitizer"));

            commands.Add(("Fix XSS: Output encoding (React/Angular/Vue)",
                "// React: JSX auto-escapes by default.\n" +
                "// <div>{userInput}</div> -- safe\n" +
                "// <div dangerouslySetInnerHTML={{__html: userInput}} /> -- DANGEROUS, avoid!\n" +
                "\n" +
                "// Angular: template syntax auto-escapes.\n" +
                "// {{ userInput }} -- safe\n" +
                "// [innerHTML]=\"userInput\" -- bypasses security, use DomSanitizer instead\n" +
                "\n" +
                "// For all frameworks: use DOMPurify for rich text\n" +
                "// npm install dompurify\n" +
                "// import DOMPurify from 'dompurify';\n" +
                "// const clean = DOMPurify.sanitize(dirty);"));
        }

        if (hasFileUpload)
        {
            commands.Add(("Fix insecure file upload",
                "# Validate extensions (whitelist approach):\n" +
                "ALLOWED_EXTENSIONS='jpg jpeg png gif pdf doc docx'\n" +
                "EXTENSION=\"${filename##*.}\"\n" +
                "if [[ ! \" $ALLOWED_EXTENSIONS \" =~ \" $EXTENSION \" ]]; then\n" +
                "    echo \"File type not allowed\" && exit 1\n" +
                "fi\n" +
                "\n" +
                "# Validate MIME type:\n" +
                "MIME=$(file --mime-type -b \"$filename\")\n" +
                "ALLOWED_MIMES='image/jpeg image/png image/gif application/pdf'\n" +
                "\n" +
                "# Store outside web root:\n" +
                "mv \"$filename\" /var/uploads/\"$(uuidgen)\".$EXTENSION\n" +
                "\n" +
                "# Scan for malware:\n" +
                "clamscan \"$filename\""));
        }

        if (hasPathTraversal)
        {
            commands.Add(("Fix path traversal",
                "# Never use user input directly in file paths:\n" +
                "// C# — use Path.GetFileName() to strip directories:\n" +
                "string safeName = Path.GetFileName(userInput);  // strips '../'\n" +
                "string filePath = Path.Combine(safeBaseDir, safeName);\n" +
                "\n" +
                "// Java:\n" +
                "String safeName = Paths.get(userInput).getFileName().toString();\n" +
                "\n" +
                "// Python:\n" +
                "import os\n" +
                "safe_name = os.path.basename(user_input)\n" +
                "\n" +
                "# Validate the resolved path stays within allowed directory:\n" +
                "real_path = os.path.realpath(os.path.join(base_dir, safe_name))\n" +
                "if not real_path.startswith(os.path.realpath(base_dir)):\n" +
                "    raise ValueError(\"Path traversal detected\")"));
        }
    }

    private static void GenerateAuthRemediations(List<(string, string)> commands, List<Vulnerability> vulns)
    {
        var hasJwt = vulns.Any(v => v.Module == "JwtAnalyzer");
        var hasWeakCreds = vulns.Any(v => v.Type.Contains("Weak Credentials"));
        var hasNoMfa = vulns.Any(v => v.Type.Contains("No MFA") && v.Module == "IamAuditor");
        var hasRootKeys = vulns.Any(v => v.Type.Contains("Root Has Access Keys"));
        var hasUserEnum = vulns.Any(v => v.Type.Contains("Username Enumeration"));
        var hasNoBruteForce = vulns.Any(v => v.Type.Contains("No Brute Force"));

        if (hasJwt)
        {
            commands.Add(("Generate a strong JWT secret",
                "# Generate a cryptographically secure 256-bit key:\n" +
                "openssl rand -base64 32\n" +
                "\n" +
                "# Or in code (C#):\n" +
                "var key = new byte[32];\n" +
                "RandomNumberGenerator.Fill(key);\n" +
                "var base64Key = Convert.ToBase64String(key);\n" +
                "\n" +
                "# Store in environment variable or secrets manager, NEVER in code:\n" +
                "export JWT_SECRET=\"$(openssl rand -base64 32)\""));

            commands.Add(("Configure proper JWT validation (C#)",
                "// In Program.cs or startup — configure JWT validation:\n" +
                "builder.Services.AddAuthentication().AddJwtBearer(options =>\n" +
                "{\n" +
                "    options.TokenValidationParameters = new TokenValidationParameters\n" +
                "    {\n" +
                "        ValidateIssuer = true,\n" +
                "        ValidIssuer = \"https://your-api.com\",\n" +
                "        ValidateAudience = true,\n" +
                "        ValidAudience = \"https://your-app.com\",\n" +
                "        ValidateIssuerSigningKey = true,\n" +
                "        IssuerSigningKey = new SymmetricSecurityKey(\n" +
                "            Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable(\"JWT_SECRET\"))),\n" +
                "        ValidateLifetime = true,\n" +
                "        ClockSkew = TimeSpan.Zero  // No tolerance for expiration\n" +
                "    };\n" +
                "});"));
        }

        if (hasWeakCreds)
        {
            commands.Add(("Implement strong password policy",
                "# /etc/security/pwquality.conf (Linux PAM):\n" +
                "minlen = 12\n" +
                "minclass = 3      # uppercase, lowercase, digits, others\n" +
                "maxrepeat = 2\n" +
                "maxsequence = 4\n" +
                "dictcheck = 1     # check against dictionary\n" +
                "\n" +
                "# Change all default passwords:\n" +
                "passwd admin        # Linux\n" +
                "passwd root         # Linux\n" +
                "\n" +
                "# MySQL:\n" +
                "ALTER USER 'root'@'localhost' IDENTIFIED BY 'strong_random_password';"));
        }

        if (hasNoMfa || hasRootKeys)
        {
            commands.Add(("Enable MFA for AWS root account and IAM users",
                "# 1. Log into AWS Console as root\n" +
                "# 2. Go to IAM → Security Credentials → Activate MFA\n" +
                "# 3. Use hardware MFA device or authenticator app\n" +
                "\n" +
                "# Enable MFA for IAM users:\n" +
                "aws iam enable-mfa-device --user-name USERNAME \\\n" +
                "  --serial-number arn:aws:iam::ACCOUNT:mfa/USERNAME \\\n" +
                "  --authentication-code1 123456 \\\n" +
                "  --authentication-code2 789012"));
        }

        if (hasRootKeys)
        {
            commands.Add(("Delete AWS root access keys",
                "# List and delete root access keys:\n" +
                "aws iam list-access-keys --user-name root\n" +
                "aws iam delete-access-key --user-name root --access-key-id AKIAXXXXXXXX\n" +
                "\n" +
                "# Create an IAM admin user for daily tasks instead:\n" +
                "aws iam create-user --user-name admin-daily\n" +
                "aws iam attach-user-policy --user-name admin-daily \\\n" +
                "  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess\n" +
                "aws iam enable-mfa-device --user-name admin-daily ..."));
        }

        if (hasUserEnum)
        {
            commands.Add(("Fix username enumeration in login",
                "# The key principle: return IDENTICAL error messages for\n" +
                "# invalid username AND invalid password.\n" +
                "\n" +
                "# Instead of:\n" +
                "# \"User not found\" vs \"Incorrect password\"\n" +
                "\n" +
                "# Always return:\n" +
                "# \"Invalid username or password\"\n" +
                "\n" +
                "# If you need password reset: always show the same message:\n" +
                "# \"If an account with that email exists, a reset link has been sent.\""));
        }

        if (hasNoBruteForce)
        {
            commands.Add(("Implement rate limiting on login endpoints",
                "# Nginx rate limiting:\n" +
                "limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;\n" +
                "\n" +
                "location /login {\n" +
                "    limit_req zone=login burst=3 nodelay;\n" +
                "    proxy_pass http://backend;\n" +
                "}\n" +
                "\n" +
                "# Or use fail2ban:\n" +
                "echo '[nginx-login]\n" +
                "enabled = true\n" +
                "filter = nginx-login\n" +
                "action = iptables-multiport[name=nginx-login, port=\"http,https\"]\n" +
                "logpath = /var/log/nginx/access.log\n" +
                "maxretry = 5\n" +
                "bantime = 600' > /etc/fail2ban/jail.d/nginx-login.conf"));
        }
    }

    private static void GenerateDatabaseRemediations(List<(string, string)> commands, List<Vulnerability> vulns)
    {
        commands.Add(("Bind database services to localhost only",
            "# MySQL (/etc/mysql/mysql.conf.d/mysqld.cnf):\n" +
            "bind-address = 127.0.0.1\n" +
            "systemctl restart mysql\n" +
            "\n" +
            "# PostgreSQL (/etc/postgresql/*/main/postgresql.conf):\n" +
            "listen_addresses = 'localhost'\n" +
            "systemctl restart postgresql\n" +
            "\n" +
            "# Redis (/etc/redis/redis.conf):\n" +
            "bind 127.0.0.1\n" +
            "requirepass YOUR_STRONG_REDIS_PASSWORD\n" +
            "systemctl restart redis\n" +
            "\n" +
            "# MongoDB (/etc/mongod.conf):\n" +
            "net:\n" +
            "  bindIp: 127.0.0.1\n" +
            "systemctl restart mongod"));

        commands.Add(("Set strong database passwords",
            "# MySQL:\n" +
            "ALTER USER 'root'@'localhost' IDENTIFIED BY 'strong_random_password';\n" +
            "FLUSH PRIVILEGES;\n" +
            "\n" +
            "# PostgreSQL:\n" +
            "ALTER USER postgres WITH PASSWORD 'strong_random_password';\n" +
            "\n" +
            "# Redis:\n" +
            "# Add to redis.conf:\n" +
            "# requirepass YOUR_STRONG_REDIS_PASSWORD\n" +
            "\n" +
            "# MongoDB:\n" +
            "use admin\n" +
            "db.createUser({user: 'admin', pwd: 'strong_random_password', roles: ['root']})"));
    }

    private static void GenerateCloudRemediations(List<(string, string)> commands, List<Vulnerability> vulns)
    {
        var hasPublicS3 = vulns.Any(v => v.Module == "S3BucketScanner" &&
            (v.Type.Contains("Public") || v.Type.Contains("Policy")));
        var hasNoEncryption = vulns.Any(v => v.Type.Contains("Encryption"));
        var hasNoVersioning = vulns.Any(v => v.Type.Contains("Versioning"));
        var hasNoLogging = vulns.Any(v => v.Type.Contains("Logging"));

        if (hasPublicS3)
        {
            commands.Add(("Block public access for all S3 buckets",
                "# Block all public access at account level:\n" +
                "aws s3control put-public-access-block --account-id YOUR_ACCOUNT_ID \\\n" +
                "  --public-access-block-configuration \\\n" +
                "  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true\n" +
                "\n" +
                "# For a specific bucket:\n" +
                "aws s3api put-public-access-block --bucket YOUR_BUCKET \\\n" +
                "  --public-access-block-configuration \\\n" +
                "  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true\n" +
                "\n" +
                "# Remove public bucket policy:\n" +
                "aws s3api delete-bucket-policy --bucket YOUR_BUCKET\n" +
                "\n" +
                "# Remove public ACL grants:\n" +
                "aws s3api put-bucket-acl --bucket YOUR_BUCKET --acl private"));
        }

        if (hasNoEncryption)
        {
            commands.Add(("Enable default encryption for S3 buckets",
                "# Enable SSE-S3 (AES-256) encryption by default:\n" +
                "aws s3api put-bucket-encryption --bucket YOUR_BUCKET \\\n" +
                "  --server-side-encryption-configuration '{\n" +
                "    \"Rules\": [{\n" +
                "      \"ApplyServerSideEncryptionByDefault\": {\n" +
                "        \"SSEAlgorithm\": \"AES256\"\n" +
                "      }\n" +
                "    }]\n" +
                "  }'"));
        }

        if (hasNoVersioning)
        {
            commands.Add(("Enable versioning on S3 buckets",
                "aws s3api put-bucket-versioning --bucket YOUR_BUCKET \\\n" +
                "  --versioning-configuration Status=Enabled"));
        }

        if (hasNoLogging)
        {
            commands.Add(("Enable S3 server access logging",
                "# Create a logging bucket first:\n" +
                "aws s3 mb s3://YOUR_BUCKET-logs\n" +
                "\n" +
                "# Set bucket ACL to allow log delivery (requires special group):\n" +
                "aws s3api put-bucket-acl --bucket YOUR_BUCKET-logs \\\n" +
                "  --grant-write URI=http://acs.amazonaws.com/groups/s3/LogDelivery \\\n" +
                "  --grant-read-acp URI=http://acs.amazonaws.com/groups/s3/LogDelivery\n" +
                "\n" +
                "# Enable logging on main bucket:\n" +
                "aws s3api put-bucket-logging --bucket YOUR_BUCKET \\\n" +
                "  --bucket-logging-status '{\n" +
                "    \"LoggingEnabled\": {\n" +
                "      \"TargetBucket\": \"YOUR_BUCKET-logs\",\n" +
                "      \"TargetPrefix\": \"access-logs/\"\n" +
                "    }\n" +
                "  }'"));
        }

        commands.Add(("Enable AWS CloudTrail for account-wide logging",
            "aws cloudtrail create-trail --name default-trail \\\n" +
            "  --s3-bucket-name YOUR_AUDIT_BUCKET \\\n" +
            "  --is-multi-region-trail \\\n" +
            "  --enable-log-file-validation\n" +
            "\n" +
            "aws cloudtrail start-logging --name default-trail"));
    }

    private static void GenerateGraphQLRemediations(List<(string, string)> commands, List<Vulnerability> vulns)
    {
        commands.Add(("Disable GraphQL introspection in production",
            "# Apollo Server (JavaScript/TypeScript):\n" +
            "const server = new ApolloServer({\n" +
            "  typeDefs,\n" +
            "  resolvers,\n" +
            "  introspection: false,  // Disable introspection\n" +
            "  playground: false       // Also disable playground\n" +
            "});\n" +
            "\n" +
            "# GraphQL.NET (C#):\n" +
            "services.AddGraphQL(b => b\n" +
            "    .AddSchema<MySchema>()\n" +
            "    .AddSystemTextJson()\n" +
            "    .Configure<GraphQLOptions>(o => o.EnableMetrics = false)  // Disable in production\n" +
            ");"));

        commands.Add(("Implement query depth limiting",
            "# graphql-depth-limit (Node.js):\n" +
            "npm install graphql-depth-limit\n" +
            "\n" +
            "import depthLimit from 'graphql-depth-limit';\n" +
            "\n" +
            "const server = new ApolloServer({\n" +
            "  schema,\n" +
            "  validationRules: [depthLimit(5)]  // Max 5 levels deep\n" +
            "});\n" +
            "\n" +
            "# Or with express-graphql:\n" +
            "app.use('/graphql', graphqlHTTP({\n" +
            "  schema,\n" +
            "  validationRules: [depthLimit(5)]\n" +
            "}));"));

        commands.Add(("Disable query batching",
            "# Apollo Link (client config):\n" +
            "# Disable batching on the server side by removing batch link\n" +
            "\n" +
            "# In Apollo Server — don't enable batching:\n" +
            "# Default behavior is no batching. If you use the batch HTTP link,\n" +
            "# remove it: use HttpLink instead of BatchHttpLink"));
    }

    private static void GenerateGeneralRemediations(List<(string, string)> commands, List<Vulnerability> vulns)
    {
        commands.Add(("Keep system packages updated",
            "# Debian/Ubuntu:\n" +
            "apt-get update && apt-get upgrade -y\n" +
            "\n" +
            "# Enable automatic security updates:\n" +
            "apt-get install -y unattended-upgrades\n" +
            "dpkg-reconfigure --priority=low unattended-upgrades\n" +
            "\n" +
            "# RHEL/CentOS/Fedora:\n" +
            "yum update -y\n" +
            "# or:\n" +
            "dnf update -y"));

        commands.Add(("Run a comprehensive security audit",
            "# Lynis (Linux security auditing tool):\n" +
            "apt-get install -y lynis\n" +
            "lynis audit system\n" +
            "\n" +
            "# OWASP ZAP (web application scanner):\n" +
            "docker run -t owasp/zap2docker-stable zap-baseline.py -t https://your-app.com\n" +
            "\n" +
            "# nikto (web server scanner):\n" +
            "apt-get install -y nikto\n" +
            "nikto -h https://your-app.com"));
    }

    /// <summary>
    /// Builds a human-readable summary of all remediation categories.
    /// </summary>
    private string BuildSummary(List<Vulnerability> vulns)
    {
        var critical = vulns.Count(v => v.Severity == "Critical");
        var high = vulns.Count(v => v.Severity == "High");
        var medium = vulns.Count(v => v.Severity == "Medium");
        var low = vulns.Count(v => v.Severity == "Low");

        var sb = new StringBuilder();
        sb.AppendLine("╔══════════════════════════════════════════╗");
        sb.AppendLine("║       REMEDIATION PLAN SUMMARY           ║");
        sb.AppendLine("╠══════════════════════════════════════════╣");
        sb.AppendLine($"║  Total Findings: {vulns.Count,-24} ║");
        sb.AppendLine($"║  Critical: {critical,-34} ║");
        sb.AppendLine($"║  High:     {high,-34} ║");
        sb.AppendLine($"║  Medium:   {medium,-34} ║");
        sb.AppendLine($"║  Low:      {low,-34} ║");
        sb.AppendLine("╠══════════════════════════════════════════╣");
        sb.AppendLine("║  FIX PRIORITY ORDER:                     ║");
        sb.AppendLine("║  1. Network & Firewall                   ║");
        sb.AppendLine("║  2. Authentication & Credentials         ║");
        sb.AppendLine("║  3. Application Code (SQLi, XSS, etc.)   ║");
        sb.AppendLine("║  4. Web Server Configuration             ║");
        sb.AppendLine("║  5. Cloud Infrastructure                 ║");
        sb.AppendLine("║  6. Database Security                    ║");
        sb.AppendLine("║  7. API & GraphQL                        ║");
        sb.AppendLine("╠══════════════════════════════════════════╣");
        sb.AppendLine("║  IMPORTANT: Test in staging first!       ║");
        sb.AppendLine("╚══════════════════════════════════════════╝");

        return sb.ToString();
    }
}
