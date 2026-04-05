<p align="center">
  <img src="assets/logo.png" alt="WP-Hijack" width="520"/>
</p>

<p align="center">
  <sup>Advanced WordPress Vulnerability Scanner &amp; AI-Powered Exploitation Framework</sup>
</p>

<p align="center">
  <!-- GitHub live stats -->
  <a href="https://github.com/kdo2064/wp-Hijack/stargazers">
    <img src="https://img.shields.io/github/stars/kdo2064/wp-Hijack?style=for-the-badge&logo=github&color=FFD700&labelColor=0d1117" alt="Stars"/>
  </a>
  <a href="https://github.com/kdo2064/wp-Hijack/network/members">
    <img src="https://img.shields.io/github/forks/kdo2064/wp-Hijack?style=for-the-badge&logo=github&color=60A5FA&labelColor=0d1117" alt="Forks"/>
  </a>
  <a href="https://github.com/kdo2064/wp-Hijack/issues">
    <img src="https://img.shields.io/github/issues/kdo2064/wp-Hijack?style=for-the-badge&logo=github&color=F87171&labelColor=0d1117" alt="Issues"/>
  </a>
  <a href="https://github.com/kdo2064/wp-Hijack/pulls">
    <img src="https://img.shields.io/github/issues-pr/kdo2064/wp-Hijack?style=for-the-badge&logo=github&color=34D399&labelColor=0d1117" alt="Pull Requests"/>
  </a>
</p>

<p align="center">
  <!-- Tech badges -->
  <img src="https://img.shields.io/badge/version-1.0.0-FF4444?style=for-the-badge&logo=github" alt="Version"/>
  <img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge" alt="MIT License"/>
  <img src="https://img.shields.io/badge/Platform-Win%20%7C%20Linux%20%7C%20macOS-6B7280?style=for-the-badge" alt="Platform"/>
</p>

<p align="center">
  <!-- AI providers badge -->
  <img src="https://img.shields.io/badge/AI-Ollama%20%7C%20OpenAI%20%7C%20Anthropic%20%7C%20Gemini-8B5CF6?style=for-the-badge&logo=openai&logoColor=white" alt="AI Providers"/>
  <!-- Visitor counter -->
  <img src="https://hits.seeyoufarm.com/api/count/incr/badge.svg?url=https%3A%2F%2Fgithub.com%2Fkdo2064%2Fwp-Hijack&count_bg=%23FF4444&title_bg=%230D1117&icon=github&icon_color=%23FFFFFF&title=Visitors&edge_flat=false" alt="Visitors"/>
</p>

<p align="center">
  <b>Built by <a href="https://github.com/kdo2064">KDO || Xpert Exploit</a></b>
  &nbsp;·&nbsp;
  <a href="https://github.com/kdo2064/wp-Hijack">⭐ Star this project</a>
  &nbsp;·&nbsp;
  <a href="https://github.com/kdo2064/wp-Hijack/issues/new">🐛 Report a Bug</a>
  &nbsp;·&nbsp;
  <a href="https://github.com/kdo2064/wp-Hijack/issues/new">✨ Request a Feature</a>
</p>

---

## 📌 Table of Contents

- [What is WP-Hijack?](#-what-is-wp-hijack)
- [Features](#-feature-comparison)
- [Installation](#️-installation)
- [Quick Start](#-quick-start)
- [CLI Reference](#-full-cli-reference)
- [Configuration](#️-configuration-configjson)
- [10-Phase Pipeline](#-10-phase-scan-pipeline)
- [Reports](#-reports)
- [Project Structure](#️-project-structure)
- [Vulnerability Database](#️-vulnerability-database)
- [Usage Examples](#-usage-examples)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [Changelog](#-changelog)
- [Legal Disclaimer](#️-legal-disclaimer)
- [Author](#-author)

---

## ⚡ What is WP-Hijack?

**WP-Hijack** is a full-featured, open-source WordPress security scanner built for
penetration testers, bug bounty hunters, and red teams. It goes far beyond simple
version detection — running a **10-phase async pipeline** from passive recon all
the way to AI-generated exploit code, with zero required API keys (supports fully
local Ollama inference).

```
wp-hijack scan https://target.com --yes-ai
```

> **Why it's different from WPScan:**
> WP-Hijack adds a full **DETECT → CONFIRM → AI EXPLOIT** chain that WPScan lacks.
> Every detected vulnerability is confirmed with an active HTTP proof-of-exploit
> before AI generates a working Python PoC, cURL command, and business-risk summary.

---

## 🔥 Feature Comparison

| Capability | WP-Hijack | WPScan |
|---|:---:|:---:|
| WordPress version detection (7 signals) | ✅ | ✅ |
| REST API discovery (`/wp-json/`) | ✅ | ✅ |
| Plugin enumeration — 53-slug wordlist | ✅ | ✅ |
| Theme enumeration — 23-slug wordlist | ✅ | ✅ |
| User enumeration (4 methods) | ✅ | ✅ |
| Sensitive file exposure (70+ paths) | ✅ | ✅ |
| XML-RPC abuse testing | ✅ | ✅ |
| REST API security checks | ✅ | ✅ |
| Login security & username oracle | ✅ | ✅ |
| Safe SQLi / XSS probes | ✅ | ❌ |
| WAF detection & bypass hints | ✅ | Limited |
| WPVulnerability.net live API | ✅ | ❌ |
| Local SQLite vuln DB (offline) | ✅ | ❌ |
| **DETECT → CONFIRM → AI EXPLOIT pipeline** | ✅ | ❌ |
| AI-generated Python PoC + cURL exploit | ✅ | ❌ |
| AI executive summary + risk scoring | ✅ | ❌ |
| AI attack chain narrative | ✅ | ❌ |
| AI false-positive filter | ✅ | ❌ |
| Dark-mode HTML report + PDF | ✅ | ❌ |
| Multi-AI (OpenAI / Anthropic / Gemini / Ollama) | ✅ | ❌ |
| Joomla / Drupal CMS detection | ✅ | ❌ |
| Exponential-backoff HTTP retry | ✅ | ❌ |
| **Zero required API keys (local Ollama)** | ✅ | ❌ |

---

## 🛠️ Installation

**Requirements:** Python 3.11+ &nbsp;·&nbsp; Git &nbsp;·&nbsp; pip

### From GitHub (recommended)

```bash
git clone https://github.com/kdo2064/wp-Hijack
cd wp-Hijack
pip install -e .
wp-hijack --version
```

### Inside a virtual environment (clean install)

```bash
git clone https://github.com/kdo2064/wp-Hijack
cd wp-Hijack
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux / macOS
source .venv/bin/activate

pip install -e .
wp-hijack --version
```

### Run 100% offline with Ollama (no API key needed)

```bash
# 1. Install Ollama from https://ollama.com
ollama pull llama3          # or any model you prefer
ollama serve                 # starts the local AI server

# 2. Set provider to ollama in config.json (already the default)
# 3. Scan with AI
wp-hijack scan https://target.com --yes-ai
```

---

## 🚀 Quick Start

```bash
# Basic scan
wp-hijack scan https://target.com

# Scan + auto AI analysis
wp-hijack scan https://target.com --yes-ai

# Deep scan — plugins/themes/SQLi/XSS + verbose output
wp-hijack scan https://target.com --cautious --verbose

# Bulk scan from file
wp-hijack scan --file targets.txt --output ./reports

# Scan without AI (fastest mode)
wp-hijack scan https://target.com --no-ai

# Interactive AI chat session after scan
wp-hijack scan https://target.com --chat

# Update vulnerability database
wp-hijack update-db
```

---

## 📋 Full CLI Reference

```
wp-hijack scan [TARGET] [OPTIONS]

Arguments:
  TARGET                  Target URL (e.g. https://example.com)

Options:
  -f, --file      PATH    Text file — one URL per line (bulk mode)
  -c, --config    PATH    Path to config.json
  -o, --output    PATH    Output directory for reports  [default: ./reports]
  -y, --yes-ai            Auto-run AI analysis, skip interactive prompt
      --no-ai             Disable all AI modules for this run
      --no-ai-prompt      Run AI in Phase 8 but skip the end-of-scan prompt
      --no-confirm        Skip active HTTP confirmation tests
      --cautious          Enable CAUTIOUS-level confirmation tests (slower, more thorough)
  -m, --markdown          Write Markdown report alongside HTML + JSON
      --chat              Start interactive AI chat session after scan
      --model     TEXT    Override AI model for this run (e.g. gpt-4o)
      --provider  TEXT    Override AI provider for this run
      --verbose           Print detailed per-finding cards

wp-hijack update-db              Update the local vulnerability database
wp-hijack update-db --years 2025 Update specific NVD year feeds
wp-hijack show-config            Display the current resolved configuration
```

---

## ⚙️ Configuration (`config.json`)

```json
{
  "ai": {
    "enabled": true,
    "provider": "ollama",
    "model": "llama3",
    "base_url": "http://localhost:11434/v1",
    "api_key": "ollama",
    "max_tokens": 4096,
    "temperature": 0.2,
    "timeout": 180
  },
  "scanner": {
    "threads": 10,
    "timeout": 15,
    "user_agent_rotation": true,
    "stealth_mode": false,
    "delay_between_requests": 0.0,
    "proxy": null,
    "verify_ssl": false
  },
  "confirmation": {
    "run_confirmations": true,
    "allow_cautious_tests": false
  },
  "exploit": {
    "auto_generate": true,
    "auto_generate_severity": ["CRITICAL", "HIGH"]
  }
}
```

### AI Providers

| Provider | `"provider"` | API Key Required | Notes |
|---|---|:---:|---|
| **Ollama** (local) | `"ollama"` | ❌ No | Free, offline, private — **recommended** |
| **OpenAI** | `"openai"` | ✅ Yes | GPT-4o, GPT-4-turbo, GPT-3.5 |
| **Anthropic** | `"anthropic"` | ✅ Yes | Claude 3 Opus / Sonnet |
| **Google Gemini** | `"gemini"` | ✅ Yes | Gemini 1.5 Pro |

---

## 🔄 10-Phase Scan Pipeline

```
Phase 0  ──  Recon             IP · GeoIP · SSL cert · server headers · page title
Phase 1  ──  WAF Detection     Fingerprint firewall · get evasion hints
Phase 2  ──  CMS Detection     WordPress / Joomla / Drupal · version (7 signals)
Phase 3  ──  Enumeration       Plugins (53 slugs) · Themes (23 slugs) · Users (4 methods)
Phase 4  ──  Active Tests      XML-RPC · REST API · login oracle · file exposure · SQLi/XSS
Phase 5  ──  VulnDB Match      Local SQLite DB + WPVulnerability.net live API
Phase 6  ──  Confirmation      Per-CVE active HTTP proof-of-exploitability
Phase 7  ──  AI Exploit Gen    Python PoC · cURL · manual steps · business impact
Phase 8  ──  AI Analysis       Exec summary · risk score (0-10) · attack chain · CVE explain
Phase 9  ──  Reports           JSON · HTML (dark mode) · PDF · Markdown
```

### The 3-Stage Core

```
 ┌──────────┐      ┌──────────┐      ┌────────────────┐
 │  DETECT  │─────▶│ CONFIRM  │─────▶│  AI  EXPLOIT   │
 └──────────┘      └──────────┘      └────────────────┘
  Local DB &         Active HTTP        ✦ Python PoC
  Live API           proof test         ✦ cURL command
  version match      per-CVE            ✦ Manual steps
                                        ✦ Business impact
```

1. **DETECT** — Match installed component versions against local vulnDB + WPVulnerability.net API
2. **CONFIRM** — Send targeted safe HTTP requests to prove the vulnerability is actually exploitable (eliminates false positives)
3. **AI EXPLOIT** — AI produces a working Python PoC, cURL one-liner, step-by-step manual exploitation guide, and business-risk summary

---

## 📊 Reports

Reports are saved to `./reports/` by default:

| Format | Filename | Description |
|---|---|---|
| **JSON** | `wp_hijack_<host>.json` | Full machine-readable scan results |
| **HTML** | `wp_hijack_<host>.html` | Dark-mode interactive report with syntax highlighting |
| **PDF** | `wp_hijack_<host>.pdf` | Printable report for clients *(requires WeasyPrint)* |
| **Markdown** | `wp_hijack_<host>.md` | Clean text report — use `--markdown` flag |

---

## 🗂️ Project Structure

```
wp_hijack/
├── cli.py                     CLI entry point (Typer)
├── scanner.py                 10-phase async pipeline orchestrator
├── recon.py                   Passive recon — IP, SSL, headers, title
├── http_client.py             Async HTTP client — UA rotation, retry, proxy
├── config.py                  Config loading & validation
├── ai/
│   ├── client.py              Provider-agnostic AI interface (OpenAI/Anthropic/Gemini/Ollama)
│   ├── exploit_generator.py   AI exploit code generation
│   ├── summary.py             Executive summary generator
│   ├── risk_scorer.py         AI risk score 0–10
│   ├── attack_chain.py        Multi-step attack narrative builder
│   ├── false_positive.py      AI false-positive filter
│   ├── waf_bypass.py          WAF bypass technique generator
│   └── chat.py                Interactive AI chat session
├── cms/                       CMS detection (WordPress, Joomla, Drupal)
├── enumerators/               Plugin (53), theme (23), user (4-method) enumeration
├── active_tests/              XML-RPC, REST API, SQLi/XSS, file exposure probes
├── pipeline/                  DETECT → CONFIRM data models
├── vulndb/                    SQLite vuln DB + WPVulnerability.net API client
├── waf/                       WAF fingerprinting & evasion hints
├── reporting/                 JSON / HTML / PDF / Markdown report writers
└── templates/                 Jinja2 HTML report template (dark mode)
```

---

## 🛡️ Vulnerability Database

WP-Hijack uses a **dual-source** strategy:

| Source | When Used | API Key |
|---|---|:---:|
| **Local SQLite DB** (`vulns.json`) | Always — offline, instant lookup | ❌ |
| **WPVulnerability.net API** | Live lookup during every scan | ❌ |

```bash
# Pull latest vulnerability data
wp-hijack update-db

# Pull specific years only
wp-hijack update-db --years 2024,2025
```

---

## 💡 Usage Examples

### Full scan — everything enabled
```bash
wp-hijack scan https://shop.example.com \
  --cautious \
  --verbose \
  --markdown \
  --yes-ai \
  --output ./reports
```

### Route through Burp Suite (intercept traffic)
```bash
# In config.json set: "proxy": "http://127.0.0.1:8080"
wp-hijack scan https://target.com --config config.json
```

### Air-gapped machine (Ollama, no internet needed)
```bash
ollama serve
wp-hijack scan https://intranet-wordpress.local --yes-ai
```

### Bug bounty bulk campaign
```bash
wp-hijack scan --file scope.txt \
  --output ./bb-reports \
  --no-ai-prompt \
  --cautious
```

### OpenAI GPT-4o override for one scan
```bash
wp-hijack scan https://target.com --provider openai --model gpt-4o --yes-ai
```

---

## 🗺️ Roadmap

> Community contributions are very welcome! Check issues tagged [`help wanted`](https://github.com/kdo2064/wp-Hijack/issues).

| Status | Feature |
|:---:|---|
| ✅ | 10-phase async scan pipeline |
| ✅ | Multi-provider AI (OpenAI / Anthropic / Gemini / Ollama) |
| ✅ | DETECT → CONFIRM → AI EXPLOIT chain |
| ✅ | Dark-mode HTML + PDF reports |
| ✅ | WAF detection & bypass hints |
| ✅ | 53-plugin + 23-theme wordlist probing |
| 🔄 | WooCommerce-specific vulnerability checks |
| 🔄 | Nuclei template export |
| 🔄 | Metasploit payload generation |
| 🔄 | GitHub Actions CI integration |
| 📋 | Web UI (Flask dashboard) |
| 📋 | Docker image |
| 📋 | Shodan integration for recon |
| 📋 | Auto-exploit chaining (multi-CVE) |

---

## 🤝 Contributing

Contributions make the open-source community great. All PRs are welcome!

### How to contribute

```bash
# 1. Fork the repo on GitHub
# 2. Clone your fork
git clone https://github.com/<your-username>/wp-Hijack
cd wp-Hijack

# 3. Create a feature branch
git checkout -b feature/my-new-feature

# 4. Make your changes and test
pip install -e .
wp-hijack scan https://test-site.com

# 5. Commit and push
git commit -m "feat: add my new feature"
git push origin feature/my-new-feature

# 6. Open a Pull Request on GitHub
```

### Areas where help is needed

- 🐛 **Bug reports** — open an [Issue](https://github.com/kdo2064/wp-Hijack/issues)
- 🔌 **New active-test modules** — add to `wp_hijack/active_tests/`
- 📚 **Vuln DB entries** — extend `wp_hijack/vulndb/vulns.json`
- 🌐 **New CMS support** — add to `wp_hijack/cms/`
- 🤖 **Better AI prompts** — improve `wp_hijack/ai/exploit_prompts.py`
- 📖 **Documentation** — fix typos, add examples

Please read the [Code of Conduct](CODE_OF_CONDUCT.md) before contributing.

---

## 📝 Changelog

### v1.0.0 — April 2026 *(Initial Release)*

- ✅ 10-phase async scan pipeline
- ✅ Multi-provider AI exploit generation (OpenAI, Anthropic, Gemini, Ollama)
- ✅ DETECT → CONFIRM → AI EXPLOIT chain
- ✅ 53-plugin + 23-theme wordlist probing (works on hardened sites)
- ✅ `wp-json` REST API CMS fingerprinting (+40 confidence signal)
- ✅ Dual vuln DB (local SQLite + WPVulnerability.net live)
- ✅ Exponential-backoff HTTP retry (3 attempts, 1s/2s backoff)
- ✅ URL validation — catches typos before scan starts
- ✅ Clean-site AI summary (not just "no findings – skipped")
- ✅ Dark-mode HTML + PDF + JSON + Markdown reports
- ✅ WAF detection with bypass hint generation
- ✅ Interactive AI chat session (`--chat`)

---

## ⚠️ Legal Disclaimer

> **This tool is strictly for authorized security testing ONLY.**
>
> You must have **explicit written permission** from the target system owner
> before running any scan. Unauthorized use is **illegal** and may result in
> criminal prosecution under the CFAA, Computer Misuse Act, or equivalent laws
> in your jurisdiction.
>
> The developer (**KDO || Xpert Exploit**) assumes **zero liability** for any
> misuse, damage, or legal consequences arising from the use of this software.
>
> **Scan only what you own or have written authorization to test.**
> **Use responsibly. Hack ethically.**

---

## 👤 Author

<table>
  <tr>
    <td align="center">
      <a href="https://github.com/kdo2064">
        <img src="https://github.com/kdo2064.png" width="80" style="border-radius:50%"/><br/>
        <sub><b>KDO || Xpert Exploit</b></sub>
      </a>
    </td>
  </tr>
</table>

- 🐙 GitHub: [github.com/kdo2064](https://github.com/kdo2064)
- 📦 Project: [github.com/kdo2064/wp-Hijack](https://github.com/kdo2064/wp-Hijack)
- 🐛 Issues: [github.com/kdo2064/wp-Hijack/issues](https://github.com/kdo2064/wp-Hijack/issues)

---

<p align="center">
  <a href="https://github.com/kdo2064/wp-Hijack">
    <img src="assets/logo.png" alt="WP-Hijack" width="200"/>
  </a>
  <br/><br/>
  <a href="https://github.com/kdo2064/wp-Hijack/stargazers">
    <img src="https://img.shields.io/github/stars/kdo2064/wp-Hijack?style=social" alt="Stars"/>
  </a>
  &nbsp;
  <a href="https://github.com/kdo2064/wp-Hijack/network/members">
    <img src="https://img.shields.io/github/forks/kdo2064/wp-Hijack?style=social" alt="Forks"/>
  </a>
  <br/><br/>
  <i>If this tool helped you, please give it a ⭐ — it really helps!</i>
  <br/>
  <i>Made for the security community — use it to protect, not to harm.</i>
</p>