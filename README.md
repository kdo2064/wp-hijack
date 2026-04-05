<p align="center">
  <img src="assets/logo.png" alt="WP-Hijack" width="480" />
</p>

<p align="center">
  <i>Advanced WordPress Vulnerability Scanner &amp; AI-Powered Exploitation Framework</i>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge" alt="MIT"/>
  <img src="https://img.shields.io/badge/AI-Ollama%20%7C%20OpenAI%20%7C%20Anthropic%20%7C%20Gemini-8B5CF6?style=for-the-badge&logo=openai&logoColor=white" alt="AI"/>
  <img src="https://img.shields.io/badge/Platform-Win%20%7C%20Linux%20%7C%20macOS-6B7280?style=for-the-badge" alt="Platform"/>
</p>

---

## What is WP-Hijack?

**WP-Hijack** is a full-featured, open-source WordPress security scanner built for
penetration testers, bug bounty hunters, and red teams. It runs a **10-phase async
pipeline** — from passive recon to AI-generated exploit code — with **zero required
API keys** (works 100% offline with Ollama).

> **DETECT → CONFIRM → AI EXPLOIT**
>
> Every vulnerability is actively confirmed with an HTTP proof-of-exploit before AI
> generates a working Python PoC, cURL command, and a business-impact summary.

---

## Highlights

| Area | What it does |
|---|---|
| **CMS Detection** | 7-signal WordPress fingerprinting incl. `/wp-json/` REST API & `Link: api.w.org` header |
| **Enumeration** | 53-slug plugin wordlist + 23-slug theme wordlist — works on hardened / CDN-fronted sites |
| **User Discovery** | 4 methods: REST API, author archives (URL + body), login oracle, XML-RPC multicall |
| **Active Tests** | XML-RPC abuse · REST API checks · login oracle · 70+ sensitive file paths · safe SQLi/XSS |
| **VulnDB** | Bundled SQLite DB (offline) + live WPVulnerability.net API — no API key required |
| **AI Workflow** | Ollama (local/free), OpenAI, Anthropic, Gemini — summaries, exploit drafting, FP filter, chat |
| **Reporting** | Dark-mode HTML · PDF · JSON · Markdown — all from one scan |
| **Resilience** | Exponential-backoff HTTP retry · URL typo detection · WAF evasion hints |

---

## Installation

```bash
git clone https://github.com/kdo2064/wp-Hijack
cd wp-Hijack
python -m venv .venv
```

```bash
# Windows
.venv\Scripts\activate

# Linux / macOS
source .venv/bin/activate
```

```bash
pip install -e .
wp-hijack --version
```

### Use Local AI — No API Key Needed

```bash
# Install Ollama from https://ollama.com, then:
ollama pull llama3
ollama serve

wp-hijack scan https://target.tld --yes-ai
```

---

## Quick Start

<p align="center">
  <img src="https://media.giphy.com/media/RbDKaczqWovIugyJmW/giphy.gif" width="420" alt="scan in action"/>
</p>

```bash
# Basic scan
wp-hijack scan https://target.tld

# Scan + auto AI analysis (no prompt)
wp-hijack scan https://target.tld --yes-ai

# Deep scan — cautious checks + verbose terminal output
wp-hijack scan https://target.tld --cautious --verbose

# Bulk scan from a file (one URL per line)
wp-hijack scan --file targets.txt --output reports

# Interactive AI chat after scan
wp-hijack scan https://target.tld --chat

# Update vulnerability database
wp-hijack update-db
```

---

## Commands & Flags

### Commands

| Command | Purpose |
|---|---|
| `wp-hijack scan <target>` | Scan a single target |
| `wp-hijack scan --file targets.txt` | Bulk scan from file |
| `wp-hijack update-db` | Refresh local vuln DB from NVD feeds |
| `wp-hijack model-list` | List available Ollama models |
| `wp-hijack model-select` | Choose and save active Ollama model |
| `wp-hijack show-config` | Print resolved config (secrets masked) |
| `wp-hijack chat-report report.json` | AI chat against an existing report |

### Scan Flags

```text
--file           Bulk mode from a text file
--config         Use a custom config file
--output         Change the report output directory
--no-ai          Disable AI for this run
--no-confirm     Skip active confirmation checks
--cautious       Slower, more thorough confirmations
--markdown       Also write a Markdown report
--chat           Start interactive AI chat after the scan
--model          Override AI model for one run
--provider       Override AI provider for one run
--verbose        Show detailed finding cards in the terminal
--yes-ai         Auto-run AI analysis (skip prompt)
--no-ai-prompt   Do not ask for AI analysis after scan
```

---

## Configuration

Default behavior is controlled through [`config.json`](config.json):

```json
{
  "ai": {
    "enabled": true,
    "provider": "ollama",
    "model": "llama3",
    "base_url": "http://localhost:11434/v1"
  },
  "scanner": {
    "threads": 10,
    "timeout": 15,
    "verify_ssl": false
  },
  "confirmation": {
    "run_confirmations": true,
    "allow_cautious_tests": false
  },
  "reporting": {
    "pdf_enabled": true,
    "html_enabled": true,
    "json_enabled": true,
    "markdown_enabled": false
  }
}
```

| Provider | `"provider"` value | API Key |
|---|---|:---:|
| Ollama (local) | `"ollama"` | No (free) |
| OpenAI | `"openai"` | Yes |
| Anthropic | `"anthropic"` | Yes |
| Google Gemini | `"gemini"` | Yes |

Run `wp-hijack show-config` to inspect the effective runtime config.

---

## Output & Reports

Reports are saved to `./reports` by default:

| Format | File | Description |
|---|---|---|
| **JSON** | `wp_hijack_<host>.json` | Full machine-readable scan data |
| **HTML** | `wp_hijack_<host>.html` | Dark-mode styled browser report |
| **PDF** | `wp_hijack_<host>.pdf` | Printable client report *(needs WeasyPrint)* |
| **Markdown** | `wp_hijack_<host>.md` | Plain-text — add `--markdown` flag |

---

## Project Layout

```text
wp_hijack/
├── cli.py               CLI entry point (Typer)
├── scanner.py           10-phase pipeline orchestrator
├── recon.py             Passive recon — IP, SSL, headers, title
├── http_client.py       Async HTTP — UA rotation, retry, proxy
├── config.py            Config loading & validation
├── ai/                  AI providers, exploit gen, chat, scoring
├── cms/                 CMS detection (WordPress, Joomla, Drupal)
├── enumerators/         Plugin / theme / user enumeration
├── active_tests/        XML-RPC, REST API, SQLi/XSS, file exposure
├── pipeline/            DETECT → CONFIRM data models
├── vulndb/              SQLite DB + WPVulnerability.net client
├── waf/                 WAF fingerprinting & evasion
├── reporting/           JSON / HTML / PDF / Markdown writers
└── templates/           Jinja2 HTML report template
```

---

## Roadmap

| Status | Feature |
|:---:|---|
| Done | 10-phase async pipeline |
| Done | Multi-AI (Ollama / OpenAI / Anthropic / Gemini) |
| Done | DETECT → CONFIRM → AI EXPLOIT chain |
| Done | 53-plugin + 23-theme wordlist probing |
| Done | Exponential-backoff HTTP retry & URL typo detection |
| Done | Dark-mode HTML + PDF + JSON + Markdown reports |
| In Progress | WooCommerce-specific vuln checks |
| In Progress | Nuclei template export |
| Planned | Docker image |
| Planned | Web dashboard (Flask) |
| Planned | Shodan recon integration |
| Planned | Auto exploit chaining (multi-CVE) |

---

## Contributing

```bash
git clone https://github.com/<your-username>/wp-Hijack
git checkout -b feature/my-feature
# make your changes
git commit -m "feat: describe your change"
git push origin feature/my-feature
# open a Pull Request on GitHub
```

| Area | Where |
|---|---|
| Bug reports | [Open an issue](https://github.com/kdo2064/wp-Hijack/issues) |
| New active-test modules | `wp_hijack/active_tests/` |
| Vuln DB entries | `wp_hijack/vulndb/vulns.json` |
| Better AI prompts | `wp_hijack/ai/exploit_prompts.py` |
| New CMS support | `wp_hijack/cms/` |

---

## Legal Disclaimer

> **Authorized use only.**
>
> You must have **explicit written permission** from the system owner before running any
> scan. Unauthorized scanning is illegal under the CFAA, Computer Misuse Act, and
> equivalent laws worldwide.
>
> The developer (**KDO || Xpert Exploit**) assumes **zero liability** for any misuse,
> damage, or legal consequences from using this software.
>
> You own the target &nbsp;|&nbsp; You have written authorization &nbsp;|&nbsp; Legal testing environment
>
> **Scan responsibly. Hack ethically.**

---

## Author

<p align="center">
  <a href="https://github.com/kdo2064">
    <img src="https://github.com/kdo2064.png" width="90" style="border-radius:50%" alt="kdo2064"/>
    <br/><b>KDO || Xpert Exploit</b>
  </a>
  <br/><br/>
  <a href="https://github.com/kdo2064">GitHub</a>
  &nbsp;·&nbsp;
  <a href="https://github.com/kdo2064/wp-Hijack/issues">Issues</a>
  &nbsp;·&nbsp;
  <a href="https://github.com/kdo2064/wp-Hijack">Project</a>
</p>

---

<p align="center">
  <img src="assets/logo.png" width="160" alt="WP-Hijack"/>
  <br/><br/>
  <a href="https://github.com/kdo2064/wp-Hijack/stargazers">
    <img src="https://img.shields.io/github/stars/kdo2064/wp-Hijack?style=social" alt="Stars"/>
  </a>
  &nbsp;&nbsp;
  <a href="https://github.com/kdo2064/wp-Hijack/network/members">
    <img src="https://img.shields.io/github/forks/kdo2064/wp-Hijack?style=social" alt="Forks"/>
  </a>
  <br/><br/>
  <sub>If WP-Hijack helped you, consider starring the repo — it means a lot.</sub>
  <br/>
  <sub>Made for the security community · use it to <b>protect</b>, not to harm.</sub>
</p>

