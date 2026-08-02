# SecKit

A modular, menu-driven **security testing toolkit** for web applications, built on .NET 8 / C#.

SecKit bundles a set of active scanners — web vulnerability tests, network/TLS checks, an AI/LLM prompt-injection tester, a crawler/fuzzer, and traffic-analysis utilities — behind a single interactive CLI (with a non-interactive mode for automation). Results are written to HTML/JSON reports.

> ⚠️ **Authorized use only.** SecKit sends real attack traffic. Only run it against systems you **own** or have **explicit written permission** to test. Unauthorized scanning may violate the U.S. CFAA, the UK Computer Misuse Act, and equivalent laws elsewhere. You are responsible for how you use this tool.

---

## Quick start

### Just want to run it? (Windows)
Double-click **`run.bat`**. It builds the project (first run only) and launches the interactive menu.

On macOS/Linux, run **`./run.sh`** from a terminal.

### From the command line
```bash
# Prerequisite: .NET 8 SDK  ->  https://dotnet.microsoft.com/download
dotnet run
```

You'll get an interactive menu. Pick a scan, enter a target, and SecKit does the rest.

---

## Features

| Module | What it does |
|---|---|
| **Vulnerability Scan** | SQL injection, XSS, CSRF, SSRF, path traversal, auth, file upload |
| **Network Scan** | Multi-threaded TCP port scan, SSL/TLS inspection, security-header analysis |
| **AI Security Test** | Prompt injection (canary-token based), function-call abuse, data leakage |
| **Site Map** | Crawler + directory/parameter fuzzer |
| **Traffic Monitor** | Live log tailing + attack-pattern detection |
| **Traffic Analysis** | GeoIP mapping, honeypot, subdomain enumeration |

### Detection philosophy
SecKit favors **evidence-based detection over signature guessing** to keep false positives low:

- **SQL injection** confirms findings three ways — DBMS error signatures that appear *only after* injecting a broken value (diffed against a clean baseline), boolean-based blind detection (TRUE condition matches the baseline page, FALSE diverges), and time-based blind detection (a `SLEEP(5)` payload measurably stalls the response). Destructive payloads (`DROP TABLE`, `xp_cmdshell`) are **not** used — detection never needs them.
- **Prompt injection** uses **canary tokens**: each payload asks the model to emit a rare marker. A finding is raised only when that marker appears *and* the response isn't just echoing the payload — so a model that correctly refuses is not flagged.

---

## Non-interactive / CI usage

```bash
seckit --scan https://target.example.com \
       --type full \
       --profile medium \
       --output ./reports \
       --i-am-authorized
```

| Flag | Description |
|---|---|
| `--scan <url>` | Target URL (required) |
| `--type <full\|vuln\|network\|ai\|map>` | Scan type (default: `full`) |
| `--profile <light\|medium\|deep>` | Scan intensity (default: `medium`) |
| `--output <path>` | Report output directory |
| `--i-am-authorized` | **Required.** Confirms you have permission to test the target. Without it, SecKit refuses to run. |

---

## Configuration

Settings live in [`appsettings.json`](appsettings.json) (auto-created on first run if missing):

- **`scanProfiles`** — `light` / `medium` / `deep` control crawl depth, page limits, timeouts, thread count, fuzz breadth, and port range.
- **`targets`** — default URLs, auth token, session cookies.
- **`proxy`** — route traffic through an HTTP proxy (e.g. Burp).
- **`customHeaders`** — headers sent with every request.
- **`output`** — report directory and format (`html`, `json`, or `both`).

---

## Building & publishing

```bash
dotnet build                 # compile
dotnet run                   # build + run interactive
dotnet publish -c Release -r win-x64   # single-file executable (also: linux-x64, osx-x64)
```

Reports and logs are written to `./reports/` by default.

---

## Project layout

```
Core/       HttpClient factory, config, logging, report generation
Models/     Vulnerability, ScanResult, SecurityReport
Modules/    One folder per scanner family (VulnerabilityScanner, NetworkScanner, AiSecurityTester, ...)
Program.cs  Interactive menu + non-interactive CLI entry point
```

Each scanner follows the same shape: a `TestAsync`/`ScanAsync` method returning a `ScanResult` full of `Vulnerability` records. Adding a new module is a copy-fill-register exercise.

---

## License & disclaimer

Provided for **authorized security testing and education only**. No warranty. The authors are not responsible for misuse or for any damage caused by running this tool.
