<div align="center">

```
   ███████╗████████╗██████╗ ██╗██╗  ██╗
   ██╔════╝╚══██╔══╝██╔══██╗██║╚██╗██╔╝
   ███████╗   ██║   ██████╔╝██║ ╚███╔╝
   ╚════██║   ██║   ██╔══██╗██║ ██╔██╗
   ███████║   ██║   ██║  ██║██║██╔╝ ██╗
   ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝
```

### STRIX — Autonomous Bug Bounty Recon & Vulnerability Triage Engine

**Silent Targeting · Recon · Intelligence · X-extractor**

Automated attack surface mapping, CVE correlation, and OWASP Top 10:2025 detection with AI-assisted triage and deterministic oracle validation — built for bug bounty hunters and security researchers who want signal, not noise.

[![Python](https://img.shields.io/badge/python-3.11+-blue?logo=python&logoColor=white)](https://www.python.org/)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010%3A2025-orange?logo=owasp&logoColor=white)](https://top10.owasp.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](#license)
[![Status](https://img.shields.io/badge/status-active-brightgreen)](#)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-blueviolet)](#contributing)
[![Made for Bug Bounty](https://img.shields.io/badge/made%20for-bug%20bounty-critical)](#)

[Overview](#what-is-strix) ·
[Features](#features) ·
[OWASP Coverage](#owasp-top-102025-coverage) ·
[Install](#installation) ·
[Usage](#usage) ·
[Output](#output) ·
[FAQ](#faq)

</div>

---

## What is STRIX?

**STRIX is an open-source, end-to-end web application security scanner** for authorized bug bounty hunting, penetration testing, and continuous attack surface monitoring. It chains subdomain enumeration, live host probing, CVE correlation, and OWASP Top 10:2025 vulnerability detection into a single automated recon-to-report pipeline — then uses an LLM strictly for **triage**, never for final judgment.

Every finding that reaches your report has passed through a **deterministic oracle**: an out-of-band callback, a response diff, a reflected/executed payload, a timing signature, or a matched detection template. The AI can flag candidates; only hard evidence can confirm them.

> **Core design rule:** detection is deterministic, the LLM only triages, and nothing is reported until an oracle proves it.

```
scope.txt
   │
   ▼
┌────────────────────────────────────────────────────────────────┐
│ 1 · RECON            subfinder/amass/crt.sh → dnsgen/puredns →   │
│                      httpx/jarm → gau/waymore/katana/urlscan →   │
│                      jsluice → ffuf → wafw00f → API schema       │
├────────────────────────────────────────────────────────────────┤
│ 2 · CVE ENGINE       tech fingerprint → CPE → NVD 2.0 → LLM      │
│                      enrich → inject (nuclei template │ probe)   │
├────────────────────────────────────────────────────────────────┤
│ 3 · AI HUNT          OWASP A01–A10 detectors → candidates →     │
│                      LLM triage (evidence-cited) → PoC synthesis │
├────────────────────────────────────────────────────────────────┤
│ 4 · AUTOPILOT        oracle ladder: OOB │ diff │ reflection │    │
│                      timing │ signature → confirmed│likely│drop  │
├────────────────────────────────────────────────────────────────┤
│ 5 · VALIDATE/NOISE   evidence gate → oracle gate → dedup → score │
├────────────────────────────────────────────────────────────────┤
│ 6 · REPORT           OWASP-mapped HTML + Markdown                │
└────────────────────────────────────────────────────────────────┘
   SQLite state behind every stage → free resume · LLM/NVD cached
```

---

## Why "zero noise"

Most automated scanners drown you in false positives. STRIX enforces three gates in **code**, not in prompts:

| Gate | Rule |
|------|------|
| **Evidence gate** | A candidate with no concrete artifact (matched string, error signature, response delta, token, header) is rejected before the LLM ever sees it. |
| **Oracle gate** | `confirmed` is only ever set by deterministic proof — OOB callback, response diff, reflected/executed payload, timing significance, header echo, file-content marker, or nuclei signature. The LLM **cannot** exceed `likely`. |
| **Dedup + score floor** | One finding per (type, host, param); confirmed-but-low-impact findings drop to a human-review queue instead of inflating the report. |

That's the difference between a report with 300 "possible XSS" rows and one with 6 real, submittable bugs.

---

## Features

- 🔎 **Full recon** — subdomain enumeration (subfinder, amass, crt.sh, assetfinder, chaos/GH hooks), permutation + resolution, live probing with tech + JARM fingerprinting, deep URL collection (gau, waymore, katana-headless, urlscan.io), JS analysis (jsluice secrets/endpoints), content discovery, WAF fingerprinting, API schema discovery (OpenAPI + GraphQL introspection).
- 🧬 **CVE correlation engine** — tech fingerprint → CPE → live NVD 2.0 lookup → LLM enrichment (exploitability + safe detection probe) → injection. Every applicable CVE becomes a test: an existing nuclei template if one exists, otherwise a synthesized non-destructive HTTP probe.
- 🎯 **OWASP Top 10:2025 detection** — automated detectors across the full current taxonomy (A01–A10).
- 🤖 **AI-assisted triage** — evidence-cited JSON verdicts; the model must quote a real artifact or return `verdict:false`.
- 📋 **PoC synthesis** — a copy-paste `curl` command attached to every non-rejected finding.
- ✅ **Autopilot confirmation** — OOB / diff / reflection / timing / signature oracles make the final call, not the model.
- 📄 **Submission-ready reports** — OWASP-mapped HTML + Markdown, per-finding PoC, executive summary, human-review queue.
- ♻️ **Resume anywhere** — SQLite entity graph; nothing is re-billed (LLM + NVD responses cached).
- 🔌 **Swappable AI backends** — OpenAI **or** fully local Ollama; alerts via ntfy, Discord, Gotify, or email.
- 🌐 **Proxy support**, multi-domain scope files, cron-friendly for continuous monitoring.

---

## OWASP Top 10:2025 coverage

| Code | Category | STRIX detectors |
|------|----------|-----------------|
| **A01** | Broken Access Control | IDOR, BAC, forced browsing, open redirect, **SSRF**, path traversal, CSRF |
| **A02** | Security Misconfiguration | missing headers, debug endpoints, directory listing, default exposure |
| **A03** | Software Supply Chain Failures | vulnerable/outdated components, CVE match, missing SRI |
| **A04** | Cryptographic Failures | weak TLS, cleartext credentials, weak JWT |
| **A05** | Injection | XSS, SQLi, NoSQLi, SSTI, CRLF (XXE/CMDi hooks) |
| **A06** | Insecure Design | manual/architectural — surfaced as report guidance |
| **A07** | Authentication Failures | JWT `alg:none`, OAuth `redirect_uri`, missing `state`/PKCE |
| **A08** | Software/Data Integrity Failures | insecure deserialization markers, missing integrity checks |
| **A09** | Security Logging & Alerting Failures | verbose errors without correlation |
| **A10** | Mishandling of Exceptional Conditions | stack traces, fail-open on malformed input |

> A06 (Insecure Design) is intentionally flagged as manual — architectural and business-logic flaws can't be proven by a scanner.

---

## Installation

### Option A — automated installer (recommended)

Put `setup.py` and `strix.py` in the same folder, then run:

```bash
python3 setup.py
```

This installs system packages (apt/brew), Go-based recon/scanner tooling, Python dependencies, captures API keys interactively, writes a `chmod 600` config to `~/.strix/.env`, and drops a global `strix` launcher into `~/.local/bin`.

```bash
python3 setup.py --yes        # non-interactive (reads keys from env vars)
python3 setup.py --no-go      # skip the slower Go tool build
python3 setup.py --uninstall  # clean removal
```

Reopen your shell, then run:

```bash
strix -d example.com
```

### Option B — manual install

```bash
git clone https://github.com/<you>/strix.git && cd strix
pip install httpx openai python-dotenv rich     # rich is optional (nicer CLI output)

# Go-based recon/scanner tooling
export GOBIN="$HOME/.local/bin"
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/BishopFox/jsluice/cmd/jsluice@latest
```

---

## Configuration

Keys live in `~/.strix/.env` (mode `600`) and are auto-loaded by the launcher.

| Variable | Required | Purpose |
|----------|:--------:|---------|
| `OPENAI_API_KEY` | ✅ | AI triage, report narrative, CVE enrichment |
| `NVD_API_KEY` | — | raises NVD rate limit (5 → 50 req/30s) |
| `URLSCAN_API_KEY` | — | urlscan.io intelligence source |
| `STRIX_OOB_SERVER` | — | out-of-band collaborator host (SSRF / blind confirmation) |
| `STRIX_LLM_BACKEND` | — | `openai` (default) or `ollama` (fully local, no data leaves the box) |
| `STRIX_OLLAMA_MODEL` | — | local model name, e.g. `qwen2.5:14b` |
| `STRIX_ALERT` | — | `none` \| `ntfy` \| `discord` \| `gotify` \| `email` |
| `NTFY_URL`, `DISCORD_WEBHOOK`, `GOTIFY_URL`, `GOTIFY_TOKEN`, `ALERT_EMAIL` | — | alerting backend credentials |
| `STRIX_PROXY` | — | HTTP proxy for all outbound requests |
| `STRIX_MIN_CVSS` | — | minimum CVE score to inject (default `5.0`) |

Optional tuning: `STRIX_TRIAGE_MODEL`, `STRIX_REPORT_MODEL`, `STRIX_RPS`, `STRIX_TIMING_REPS`, `STRIX_TIMING_FACTOR`, `STRIX_LIKELY`, `STRIX_MIN_SCORE`.

> **Security note:** never commit `.env` files or API keys to version control. Rotate any key immediately if it is accidentally exposed in a commit, log, or shared document.

---

## Usage

```bash
strix -d example.com              # full pipeline (default)
strix scan     -d example.com --skip-cve
strix recon    -d example.com     # phase 1 only — attack surface mapping
strix cve      -d example.com     # CVE match + injection
strix owasp    -d example.com     # OWASP A01–A10 detection + validate
strix triage   -d example.com     # LLM triage + PoC synthesis
strix validate -d example.com     # de-noise, show clean confirmed set
strix findings -d example.com -s confirmed
strix coverage -d example.com     # OWASP coverage matrix
strix report   -d example.com -o ./out
strix resume   -d example.com     # continue an interrupted run; nothing re-billed
strix alert-test
strix init                        # verify tooling + database
```

### Multi-domain scope

```bash
while read d; do strix -d "$d"; done < scope.txt
```

### Continuous monitoring (cron)

```bash
0 */6 * * * cd /opt/strix && while read d; do strix -d "$d"; done < scope.txt >> /var/log/strix.log 2>&1
```

---

## Output

```
out/
├── report.html     # OWASP-mapped, styled, submission-ready
└── report.md       # Markdown equivalent
state.db            # SQLite entity graph (resume + cache)
```

Each confirmed finding carries: OWASP code, CWE ID, severity, confidence score, the confirming oracle, request/response evidence, and a copy-paste `curl` PoC.

---

## How a finding moves through STRIX

```
detector emits candidate (with evidence object)
        │
        ▼
[evidence gate]  ── no artifact ──► rejected (before the LLM ever sees it)
        │
        ▼
[LLM triage]  ── must cite an artifact ──► else rejected
        │
        ▼
[oracle ladder]  OOB │ diff │ reflection │ timing │ signature
        │                    │
        │             ┌──────┴──────┐
        ▼             ▼             ▼
    confirmed      likely        rejected
   (auto-report) (human queue)  (dropped)
        │
        ▼
[dedup + score floor] ──► submission-ready report
```

---

## Example run

```bash
$ strix -d target.com

  [1/6] RECON
  ▸ subs=412 live=87 urls=15342
  [2/6] CVE ENGINE
  ▸ matched 23 CVEs (cvss≥5.0)
  [3/6] OWASP A01–A10 DETECTION
  ▸ A01 done  ▸ A02 done  ...  ▸ A10 done
  [4/6] AI TRIAGE + PoC
  ▸ candidates=41
  [5/6] VALIDATE + DE-NOISE
  ▸ confirmed=6 likely=3 dropped=18 deduped=11 pruned=2
  [6/6] REPORT
  ✔ done → report.html (6 confirmed, 3 likely)
```

---

## Requirements

- Python 3.11+
- Go 1.21+ (for recon/scanner tooling)
- Linux, macOS, or WSL2
- Optional: local Ollama for fully offline AI, a self-hosted OOB collaborator for SSRF/blind-class confirmation

---

## FAQ

**Is STRIX a fully autonomous exploit tool?**
No. STRIX automates *recon, correlation, and evidence-based confirmation*. It does not perform destructive testing and does not replace manual verification before submission.

**Does the AI decide what's a real vulnerability?**
No. The LLM can only triage candidates down to `likely` at most. A finding is only marked `confirmed` by a deterministic oracle (OOB callback, response diff, reflected payload, timing signature, or template match).

**Can I run it fully offline?**
Yes — set `STRIX_LLM_BACKEND=ollama` and point it at a local model. Recon/scanning tooling still needs network access to the target, but no data has to leave your machine for the AI portions.

**Is this legal to run against any domain?**
Only against assets you own or are explicitly authorized to test under a bug bounty or pentest agreement. See [Legal / authorized use](#legal--authorized-use).

---

## Legal / authorized use

STRIX is built for **authorized security testing only** — bug bounty programs, internal assessments, and CTFs against assets you own or are explicitly permitted to test. The CVE injection engine and generic probes are non-destructive by default (`STRIX_ALLOW_DESTRUCTIVE=0`), but you remain solely responsible for staying in scope and honoring each program's rules. Always confirm authorization before scanning a target.

---

## Roadmap

- [ ] Playwright DOM-execution oracle for XSS (reflection → real execution)
- [ ] Authenticated OpenAPI-driven scan mode (reach post-auth A01/A07 surfaces)
- [ ] CI/CD supply-chain probing for A03
- [ ] Nuclei/SARIF export
- [ ] Docker image

---

## Contributing

PRs welcome. Keep the two invariants intact: **deterministic detection** and **oracle-based confirmation**. A new detector must emit a structured evidence object and a matching oracle entry.

```bash
https://github.com/tanvirahmedcs/STRIX.git
cd strix
python3 -m venv .venv && source .venv/bin/activate
python3 setup.py
pip install -e .
```

---

## License

MIT — see [LICENSE](LICENSE).

---

<div align="center">

<sub>Built for people who find real bugs, not bug-shaped noise.</sub>

<sub>**Keywords:** bug bounty automation · OWASP Top 10:2025 scanner · CVE correlation tool · subdomain enumeration · attack surface management · AI-assisted vulnerability triage · penetration testing recon pipeline</sub>

</div>
