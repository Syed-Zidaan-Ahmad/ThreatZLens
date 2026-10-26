<!-- Threat Z Lens (Documentation Part) -->
# 🛡️ Threat Z Lens

## ⚡ Next-Gen Cyber Threat Intelligence Aggregator & Attack Chain Visualizer

> 👁️ **SEE THE THREAT BEFORE IT STRIKES**  
> **Project by : Zidaan**  
> Try it here [Threat Z Lens](https://threat-z-lens.onrender.com/)  
> 💎 **Signature Branding**: Features the distinctive neon cyan **Z** (`#0ef`) brand signature representing author Zidaan, ensuring this project remains uniquely identifiable.

Threat Z Lens is a fast, browser-based threat intelligence platform and Progressive Web App (PWA) that I built to help security analysts, incident responders, and researchers investigate suspicious indicators of compromise (IoCs) in seconds.

Instead of manually jumping across five different websites to check a phishing email or server log, Threat Z Lens lets you paste raw text or drop a log file into one clean command center. It automatically pulls out all the links, IPs, domains, hashes, and CVEs, checks them against live security feeds (**VirusTotal** and **AlienVault OTX**), calculates a clear 0–100 risk score with transparent math, and gives you actionable containment rules ready to copy-paste.

---

## ✨ Why I Built Threat Z Lens

Whenever I investigated phishing alerts or suspicious server logs, the workflow always felt slow and fragmented:

1. You have to manually defang URLs and clean up text.
2. You open multiple tabs: VirusTotal, AlienVault OTX, WHOIS lookup, and CVE databases.
3. You have to make sure you never accidentally click or trigger an internal/private IP (avoiding SSRF).
4. Most tools give you a vague "High / Low" risk without explaining how they calculated it.
5. Drafting blocking rules for firewalls and writing incident response notes takes extra time.

I built **Threat Z Lens** to solve this entire workflow in one place. You paste the raw message or log, and Threat Z Lens does the heavy lifting: extracting indicators, isolating private network addresses, checking global threat databases, calculating a weighted score, rendering an interactive attack chain graph, and drafting firewall rules for your defense stack.

The goal isn't to replace human analysts—it's to give them clear, reliable data and fast tools so they can make confident decisions before a threat causes damage.

---

## 🚀 Key Features

- 🔍 **Automatic IoC Extraction & Refanging**: Finds and extracts URLs (`hxxp://`, `[.]`, `[:]`), domains, IPv4 addresses, emails, cryptographic hashes (MD5, SHA1, SHA256), and CVE IDs. Includes one-click Defang / Refang buttons.
- 🛡️ **Built-in SSRF Defense**: Inspects all extracted IPs and skips RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopbacks (`127.0.0.1`), link-local addresses, and AWS metadata endpoints (`169.254.169.254`), showing them safely in a separate skipped list.
- 🌐 **Dual Threat Intelligence Feeds**: Live asynchronous correlation with **VirusTotal API v3** (vendor engine stats & community reputation) and **AlienVault OTX** (community threat pulses and malware tags).
- 🧮 **Transparent 0–100 Risk Scoring**: No black-box magic. A deterministic formula based on vendor detection ratios, community pulse counts, and malware keywords, backed by an Anti-Dilution rule.
- 🤖 **48 Modern AI Models Supported**: Choose between 48 frontier and open-weight models across 13 providers (Google Gemini, Anthropic Claude, OpenAI, IBM Cloud / watsonx Granite, Groq, DeepSeek, xAI Grok, NVIDIA, Perplexity, Cohere, Mistral, Meta Llama, and Qwen) arranged with zero provider repetition per page.
- 🔑 **Bring-Your-Own-Key (BYOK) Privacy**: Slide-down settings drawer to enter your own AI or threat feed API keys. Keys stay strictly in your browser's `localStorage` and are never saved to a database.
- 🕸️ **Interactive Force-Directed Threat Graph**: An animated 2D Canvas graph showing how the target, phishing lure, C2 servers, CVEs, and file hashes connect, complete with draggable nodes and flowing data particles.
- 🎯 **MITRE ATT&CK Matrix Mapping (v15)**: Automatically maps detected threats to enterprise tactics like Initial Access (T1566), Execution (T1204), Exploitation (T1203), and Command & Control (T1071).
- 🧱 **One-Click Firewall Rules**: Instantly compiles blocking rules for Linux iptables, Cisco ASA, AWS WAF IPSet, Windows Defender PowerShell, and DNS Sinkhole hosts.
- 💬 **Interactive SOC Analyst AI Chat**: Ask follow-up questions about the scan results, get remediation steps, or click one button to generate a formatted incident response ticket.
- ⏱️ **Smart Timezone Clock (Auto-Detects IST / Local & UTC)**: Automatically detects your local time (e.g. `IST: HH:MM:SS` for India Standard Time or your local browser timezone) with a 1-click interactive toggle to switch to Zulu SOC UTC time.
- 🔊 **Web Audio Cyber SFX**: Synthesizes futuristic audio feedback for scans, warnings, and button clicks using the native Web Audio API (with an easy Mute button).
- 📱 **Installable Progressive Web App (PWA)**: Works as a standalone desktop or mobile web app with offline caching and an in-app `📲 Install App` button.
- 📄 **One-Click Export**: Download an executive PDF report (`html2pdf.js`), raw JSON, or CSV for your records.
- 🚦 **Cyber Traffic Light Scrollbars**: Interactive cyber scrollbar dynamics across the main document and AI Models modal (idle threat red #ff4c4c, turning bright cyber green #00ff9d on hover, grab, or active scrolling).
- 🧪 **Offline & Demo Mode**: Pre-loaded with realistic samples (Phishing with CVE-2023-38831, Mixed Threat, and Clean Corporate traffic) so anyone can test the full pipeline without needing API keys.

---

## 🔄 How the Workflow Operates

```text
Raw Security Input (Pasted Text or Uploaded Log)
                   ↓
      Input Capture & Refanging
  (Converts hxxp://, [.], etc. into clean IoCs)
                   ↓
      SSRF Subnet & Loopback Filter
     (Safely quarantines RFC 1918 & 127.0.0.1)
                   ↓
       In-Memory TTL Cache Check
         (1-Hour Cache for Fast Re-use)
                   ↓
       Dual Threat Feed Querying
    ┌──────────────┴──────────────┐
    ↓                             ↓
VirusTotal API v3         AlienVault OTX API
(Engines & Ratios)        (Threat Pulses)
    └──────────────┬──────────────┘
                   ↓
      Deterministic Risk Scoring
    (Transparent 0–100 Mathematical Policy)
                   ↓
       AI Threat Synthesis & Triage
       (48 Frontier & Open AI Models)
                   ↓
 ┌─────────────────┼─────────────────┐
 ↓                 ↓                 ↓
Threat Graph    MITRE ATT&CK    Defense Rules
(Interactive)   (Tactics v15)   (iptables/AWS)
                   ↓
        Final Decision Verdict
    (CLEAN / SUSPICIOUS / MALICIOUS)
                   ↓
     Local History & PDF/JSON Export
```

### Final Verdict Categories

```text
CLEAN        (0 – 14)   : Confirmed safe across authoritative intelligence feeds
SUSPICIOUS   (15 – 49)  : Moderate risk, low reputation, or targeted community pulses
MALICIOUS    (50 – 100) : Confirmed weaponized infrastructure, phishing kit, or exploit
UNKNOWN      (N/A)      : Lookups rate-limited or uncataloged (never falsely labeled Clean)
```

---

## 🧠 Step-by-Step System Breakdown

### 1. 📥 Input Capture & Autonomous Refanging

You can bring data into Threat Z Lens in three simple ways:
- **Direct Paste**: Paste email headers, raw firewall logs, or chat transcripts into the main box.
- **File Upload**: Drop `.txt`, `.eml`, `.log`, or `.csv` files (up to 2 MB).
- **Sample Presets**: Click one of the three built-in scenario buttons (Phishing Lure, Mixed Incursion, or Clean Corporate Infrastructure).

Before anything else happens, Threat Z Lens automatically normalizes defanged indicators:
- `hxxp://` and `hxxps://` $\rightarrow$ `http://` and `https://`
- `bad-domain[.]com` and `bad-domain(.)com` $\rightarrow$ `bad-domain.com`
- `192[.]168[.]1[.]1` $\rightarrow$ `192.168.1.1`
- `user[@]target[.]com` $\rightarrow$ `user@target.com`

### 2. 🛡️ SSRF Protection & Private IP Quarantine

Threat Z Lens **never opens or visits user-provided URLs**. All outbound HTTP requests are strictly limited to official threat API endpoints.

To protect internal networks, every extracted IP address is checked against private network ranges:
- **Loopback**: `127.0.0.0/8`
- **RFC 1918 Private Ranges**: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- **Link-Local**: `169.254.0.0/16` (including AWS metadata `169.254.169.254`)
- **Multicast & Reserved**: `224.0.0.0/4`, `240.0.0.0/4`

Any address matching these ranges is moved to the **Skipped Indicators** drawer with an explanation. This gives you full visibility of internal IPs without putting your internal network at risk.

### 3. 🌐 Live Threat Intelligence Queries

Every valid public indicator is checked against two global intelligence providers:

- **VirusTotal API v3**:
  - Checks detection results across 70+ antivirus and security engines.
  - Calculates the exact ratio of malicious and suspicious verdicts.
  - Pulls community reputation scores.
  - Uses an in-memory token-bucket rate limiter (4 requests/minute) so you never breach public API limits.

- **AlienVault OTX**:
  - Checks if the indicator appears in active threat pulses submitted by the global security community.
  - Pulls tagged malware families and adversary groups.

To keep things fast and avoid burning your API quota, an in-memory **TTL Cache** stores lookup results for 1 hour (3,600 seconds). If you scan the same indicator twice, it loads instantly from cache.

### 4. 🧮 The Risk Scoring Formula (No Black Boxes)

Instead of relying on an arbitrary score, I designed a deterministic formula bounded between **0 and 100**:

$$\text{IoC Score} = \min\left(100.0, \, \text{VT Points} + \text{OTX Points} + \text{Corroboration Points}\right)$$

#### A. VirusTotal AV Detection Ratio (Up to 60 Points)
Measures what proportion of security vendors flagged the indicator:

$$\text{Detection Ratio} = \frac{\text{Malicious Engines} + 0.5 \times \text{Suspicious Engines}}{\text{Total Engines}}$$

- If the detection ratio is $\ge 20\%$ or at least 10 vendors flag it: **60 points** (Full malicious score).
- If between $0\%$ and $20\%$: Points scale proportionally: $60.0 \times \left(\frac{\text{Ratio}}{0.20}\right)$.
- Zero detections: **0 points**.

#### B. AlienVault OTX Pulse Frequency (Up to 25 Points)
Logarithmic scaling based on how many community threat pulses reference the indicator:

$$\text{OTX Points} = \min\left(25.0, \, \max\left(0.0, \, 8.0 + 8.5 \times \log_{10}(\text{Pulses})\right)\right)$$

- **1 pulse** = 8.0 points
- **3 pulses** = 12.0 points
- **10 pulses** = 16.5 points
- **100+ pulses** = 25.0 points

#### C. Threat Keywords & Reputation (Up to 15 Points)
- **Malware or Exploit Tags (+10 pts)**: Awarded if OTX or VirusTotal tags the indicator with high-threat terms like `ransomware`, `stealer`, `c2`, `trojan`, `botnet`, or `cve`.
- **Negative Community Trust (+5 pts)**: Awarded if VirusTotal community reputation drops below $-5$.

#### D. Overall Scan Score (Anti-Dilution Policy)
To make sure a real threat doesn't get hidden when mixed with many safe domains:

$$\text{Weighted Score} = 0.70 \times \max(\text{IoC Scores}) + 0.30 \times \operatorname{avg}(\text{IoC Scores})$$

If the worst indicator has a score of $\ge 50$, the overall scan score is locked to **at least $\max(\text{IoC Scores})$**. This guarantees that a single ransomware hash mixed with 10 clean company domains will always trigger a Malicious alert.

### 5. 🤖 48 Multi-Provider AI Models (With Zero Provider Repetition)

Threat Z Lens includes a curated catalog of **48 modern AI models** organized into an 8-page selector. Every single page features **six completely distinct providers** so you can easily compare different frontier models side by side:

| Page | Card 1 | Card 2 | Card 3 | Card 4 | Card 5 | Card 6 |
|:---:|:---|:---|:---|:---|:---|:---|
| **1** | Gemini 3.8 Flash | Claude 3.7 Sonnet | GPT-4o | **IBM Bob (watsonx)** | Groq Llama 3.3 70B | DeepSeek R1 |
| **2** | Gemini 3.8 Extended Thinking | Claude 3.5 Sonnet | OpenAI o3-mini | xAI Grok 3 | NVIDIA Nemotron 70B | Perplexity Sonar Pro |
| **3** | Gemini 3.0 Pro | Claude 3.5 Haiku | OpenAI GPT-4o Mini | Groq Llama 3.1 8B | xAI Grok 2 | DeepSeek V3 |
| **4** | Gemini 3.1 Pro | Claude 3.5 Opus | OpenAI o1 | Mistral Large Latest | Cohere Command R+ Latest | Meta Llama 3.3 70B |
| **5** | Gemini 3.0 Flash | OpenAI o1-mini | DeepSeek Coder V3 | Qwen 2.5 Coder Latest | Mistral Codestral Latest | Cohere Command R Latest |
| **6** | Gemini 2.0 Flash | Claude 3.5 Sonnet V2 | OpenAI GPT-4.5 | Groq DeepSeek R1 70B | xAI Grok 3 Mini | Meta Llama 3.1 8B |
| **7** | OpenAI GPT-4o Latest | NVIDIA Llama 3.3 70B | Qwen 2.5 72B | Mistral Pixtral 12B | DeepSeek R1 Qwen 32B | Meta Llama 3.1 405B |
| **8** | Gemini 3.0 Pro Preview | OpenAI o3 | Groq Llama 3.2 11B | Mistral Small Latest | Perplexity Sonar | OpenRouter Auto |

Every card has a direct **"Get API Key"** link that takes you straight to that provider's console.

#### 📋 Complete 48-Model Directory (All Supported Frontier & Open-Weight Models)

| # | Model Name | API Identifier | Provider | Primary Cybersecurity Focus |
|:---:|:---|:---|:---|:---|
| **1** | Gemini 3.8 Flash | `gemini-3.8-flash` | Google Gemini | Instant Zero-Cost Link & IP Triage (100% Free Tier) |
| **2** | Claude 3.7 Sonnet | `claude-3-7-sonnet` | Anthropic Claude | Hybrid Reasoning, Hidden Attack Traps & Forensic Analysis |
| **3** | OpenAI GPT-4o | `gpt-4o` | OpenAI | Flagship Omni Triage, Fast Summarization & Safety Guidance |
| **4** | IBM Bob | `ibm/bob` | IBM Cloud / watsonx | Enterprise Security Agent, Secret Scanning & Strict Compliance |
| **5** | Groq Llama 3.3 70B | `groq/llama-3.3-70b-versatile` | Groq Cloud | Ultra-Fast 100% Free LPU Inference & Automated Firewall Rules |
| **6** | DeepSeek R1 | `deepseek-r1` | DeepSeek | Step-by-Step Cognitive Logic & Deceptive Threat Correlation |
| **7** | Gemini 3.8 Extended Thinking | `gemini-3.8-live-extended-thinking` | Google Gemini | Deep-Thinking Multi-Stage Attack Chain Reconstruction |
| **8** | Claude 3.5 Sonnet | `claude-3.5-sonnet` | Anthropic Claude | Threat Actor Attribution & Adversary Objective Mapping |
| **9** | OpenAI o3-mini | `o3-mini` | OpenAI | Fast Cyber Reasoning & Software Vulnerability Triage |
| **10** | xAI Grok 3 | `grok-3` | xAI Grok | Real-Time Live Scams, Brand Phishing & Fast Threat Telemetry |
| **11** | NVIDIA Nemotron 70B | `nvidia/llama-3.1-nemotron-70b` | NVIDIA NIM | Enterprise NIM Reasoning & Firewall Rule Generation |
| **12** | Perplexity Sonar Pro | `sonar-pro` | Perplexity AI | Real-Time Live Web OSINT & Domain Registration Auditing |
| **13** | Gemini 3.0 Pro | `gemini-3.0-pro` | Google Gemini | Premier Deep Reasoning for Complex Multi-Vector Incidents |
| **14** | Claude 3.5 Haiku | `claude-3-5-haiku` | Anthropic Claude | Sub-Second Rapid Header, Link & Email Verification |
| **15** | OpenAI GPT-4o Mini | `gpt-4o-mini` | OpenAI | Fast Everyday Security Reviews & Remediation Guidance |
| **16** | Groq Llama 3.1 8B | `groq/llama-3.1-8b-instant` | Groq Cloud | Ultra-Low Latency (<100ms) Free IP & Domain Filtering |
| **17** | xAI Grok 2 | `grok-2` | xAI Grok | Credential Harvesting & Phishing Lure Profiling |
| **18** | DeepSeek V3 | `deepseek-v3` | DeepSeek | High-Throughput MoE Batch Indicator & Hash Scanning |
| **19** | Gemini 3.1 Pro Preview | `gemini-3.1-pro-preview` | Google Gemini | Advanced Zero-Day Threat Containment & Mitigation Preview |
| **20** | Claude 3.5 Opus | `claude-3.5-opus` | Anthropic Claude | Deep Analytical Reports & Executive Leadership Briefings |
| **21** | OpenAI o1 | `o1` | OpenAI | Deliberate High-Confidence Cognitive Threat Verification |
| **22** | Mistral Large Latest | `mistral-large-latest` | Mistral AI | Multilingual Exploit Decoding, Backdoors & Code Analysis |
| **23** | Cohere Command R+ Latest | `command-r-plus-latest` | Cohere | Grounded Enterprise Verification & Threat Intelligence Feeds |
| **24** | Meta Llama 3.3 70B | `meta/llama-3.3-70b` | Meta Llama | Open-Weights Log Analysis & Firewall Rule Compilation |
| **25** | Gemini 3.0 Flash | `gemini-3.0-flash` | Google Gemini | Modern Fast Everyday Guard (100% Free API Key Available) |
| **26** | OpenAI o1-mini | `o1-mini` | OpenAI | Compact Script, Command & Protocol Anomaly Diagnosis |
| **27** | DeepSeek Coder V3 | `deepseek-coder-v3` | DeepSeek | Next-Gen Payload Deobfuscation (JavaScript & PowerShell) |
| **28** | Qwen 2.5 Coder Latest | `qwen-2.5-coder-latest` | Alibaba Qwen | Web Shells, Malicious Macros & Exploit Script Auditing |
| **29** | Mistral Codestral Latest | `codestral-latest` | Mistral AI | Obfuscated Software Vulnerabilities & Repository Auditing |
| **30** | Cohere Command R Latest | `command-r-latest` | Cohere | Rapid Document Scanning & Malicious Signature Triage |
| **31** | Gemini 2.0 Flash | `gemini-2.0-flash` | Google Gemini | Fast Multimodal Link & Email Verification (Free Tier) |
| **32** | Claude 3.5 Sonnet V2 | `claude-3-5-sonnet-v2` | Anthropic Claude | Advanced Forensic Defense & Dependable Attribution |
| **33** | OpenAI GPT-4.5 | `gpt-4.5-preview` | OpenAI | Massive Frontier Model for Plain-Language Incident Summaries |
| **34** | Groq DeepSeek R1 70B | `groq/deepseek-r1-distill-llama-70b` | Groq Cloud | Free Distilled R1 Reasoning Running at Lightning LPU Speed |
| **35** | xAI Grok 3 Mini | `grok-3-mini` | xAI Grok | Fast Real-Time Gut-Checks on Live Online Scams |
| **36** | Meta Llama 3.1 8B | `meta/llama-3.1-8b` | Meta Llama | Lightweight Edge Triage & Rapid IP Reputation Guard |
| **37** | OpenAI GPT-4o Latest | `gpt-4o-latest` | OpenAI | Continuous Flagship Omni for Comprehensive Intelligence |
| **38** | NVIDIA Llama 3.3 70B | `nvidia/llama-3.3-70b-instruct` | NVIDIA NIM | Accelerated NIM Infrastructure for Complex Technical Logs |
| **39** | Qwen 2.5 72B | `qwen-2.5-72b` | Alibaba Qwen | Powerful Logic for Unraveling Scrambled Scripts & Downloads |
| **40** | Mistral Pixtral 12B | `mistral-pixtral-12b` | Mistral AI | Visual Phishing Specialist (Deceptive Logos & Fake Logins) |
| **41** | DeepSeek R1 Qwen 32B | `deepseek-r1-distill-qwen-32b` | DeepSeek | High-Precision Distilled Reasoning for Cyber Threat Triage |
| **42** | Meta Llama 3.1 405B | `meta/llama-3.1-405b` | Meta Llama | Titan Open Intelligence for Deep Multi-Event Correlation |
| **43** | Gemini 3.0 Pro Preview | `gemini-3.0-pro-preview` | Google Gemini | Frontier Context Pioneer for Massive Security Log Audits |
| **44** | OpenAI o3 | `o3` | OpenAI | State-of-the-Art Cognitive Reasoning for Zero-Day Threats |
| **45** | Groq Llama 3.2 11B | `groq/llama-3.2-11b-vision-preview` | Groq Cloud | Free Fast Multimodal Model for Phishing Form & URL Checks |
| **46** | Mistral Small Latest | `mistral-small-latest` | Mistral AI | Enterprise-Grade Lightweight European Triage & Auditing |
| **47** | Perplexity Sonar | `sonar` | Perplexity AI | Rapid OSINT Web Research across Public Security Forums |
| **48** | OpenRouter Auto | `openrouter/auto` | OpenRouter | Universal Fallback Router Dynamically Selecting Optimal Model |

### 6. 🛡️ Prompt Injection Defense

I designed strict boundaries so untrusted input can never hijack the AI:
- The AI never receives raw executable code or unstructured instructions directly.
- The indicator telemetry is wrapped inside XML/markdown boundaries (`<<< >>>`).
- The system prompt instructs the model to act strictly as a SOC analyst and return validated JSON only.
- Common prompt injection phrases like `ignore previous instructions` or `system prompt override` are checked and stripped.

### 7. ⏱️ Smart Timezone Clock (Auto-Detects IST & Local vs. Zulu UTC)

When triaging security incidents, knowing exact incident timestamps in your local time is critical:
- Threat Z Lens checks your browser's timezone using `Intl.DateTimeFormat`.
- If you're in India, it automatically labels and renders **`IST: HH:MM:SS`** (Indian Standard Time).
- If you're anywhere else in the world, it auto-detects and displays your local regional timezone.
- You can **click directly on the clock** in the navbar to toggle back and forth between your **Local Time** and international **Zulu SOC UTC Time**. The app plays a cyber click sound and remembers your preference in `localStorage`.

---

## 🏗️ Technology Stack

### Frontend
- **HTML5 & CSS3**: Custom cyberpunk dark UI with glassmorphic cards, neon accents, and responsive layout. Zero external CSS frameworks needed.
- **Vanilla JavaScript (ES6+)**: Fast, clean, native code with zero heavy frontend dependencies.
- **Web Audio API**: Real-time sound synthesizer generating telemetry tones without loading external MP3 files.
- **HTML5 Canvas 2D**: Interactive physics-based force-directed attack chain graph with particle animations.
- **html2pdf.js**: Client-side executive PDF report generator.
- **PWA Support**: W3C Web App Manifest and Service Worker for desktop/mobile installation and offline shell caching.

### Backend
- **Python 3.11+ & FastAPI**: Modern, high-performance async framework.
- **Uvicorn**: Lightweight ASGI web server with dynamic port detection.
- **HTTPX**: Asynchronous HTTP client for non-blocking external API calls.
- **Pydantic v2**: Strict request and response data validation.
- **SlowAPI**: Route-level rate limiting.
- **Token Bucket Limiter**: In-memory rate limiter strictly enforcing VirusTotal public tier quotas.
- **In-Memory TTL Cache**: Concurrency-safe cache with 1-hour expiration.

### External Feeds & AI
- **VirusTotal API v3**
- **AlienVault OTX DirectConnect API**
- **13 AI Providers**: Google AI Studio, Anthropic, OpenAI, IBM Cloud / watsonx, GroqCloud, DeepSeek, xAI, NVIDIA NIM, Perplexity, Cohere, Mistral, Meta Llama, Alibaba Qwen.

### Container & Testing
- **Docker**: Hardened multi-stage container build.
- **Pytest**: 18 automated unit and integration tests (100% passing).

---

## 📁 Project Structure

Threat Z Lens is deliberately organized into **13 clean project files**:

```text
Threat-Lens/
│
├── frontend/
│   ├── index.html          # Main UI layout, header, modals, and templates
│   ├── style.css           # Glassmorphism styling, gauges, and animations
│   ├── script.js           # App logic, graph physics, audio synth, and PWA logic
│   ├── serviceworker.js    # Service worker with offline shell caching
│   ├── manifest.json       # PWA manifest (maskable and standard icons)
│   ├── icon192.png         # 192x192 cyber shield icon
│   └── icon512.png         # 512x512 cyber shield icon
│
├── backend/
│   ├── main.py            # FastAPI app, SSRF filter, scoring logic, and routes
│   └── requirements.txt    # Pinned Python package dependencies
├── DOCKERFILE              # Production Dockerfile
├── .env                    # Environment configuration template
└── ReadME.md               # Complete project documentation
```

---

## 🖥️ Frontend Overview

The frontend gives you a comprehensive command center:

- **Command Header**:
  - Smart Auto-Detecting Clock: Shows **IST** (Indian Standard Time) or your local timezone with a 1-click toggle to Zulu UTC Time.
  - Audio SFX Toggle (`M` shortcut) with synthesized acoustic feedback.
  - Active AI Model Pill and BYOK Settings Modal.
  - Keyboard Shortcuts Guide (`?` shortcut).
  - PWA `📲 Install App` Button.
  - Watermark: `Project by : Zidaan`.

- **Triage Console**:
  - Live Paste area with real-time character counter.
  - File Dropzone for `.txt`, `.eml`, `.log`, and `.csv` files.
  - One-click Demo Scenario buttons (Phishing Lure, Mixed Incursion, Clean Infrastructure).
  - Live Indicator Stream pill bar showing detected IoCs before you even click Scan.
  - One-click Defang / Refang mutators (`Alt+D`).

- **Results Dashboard**:
  - Prominent Verdict Banner (`CLEAN`, `SUSPICIOUS`, or `MALICIOUS`).
  - Conic-gradient gauges for Risk, Malicious Ratio, and Evidence Confidence.
  - SVG Indicator Category Donut Chart.
  - AI Threat Synthesis Card explaining why the indicators are dangerous and what actions to take.
  - Filterable IoC Findings Table with copy buttons and external search links.
  - Quarantined Skipped Indicators drawer for SSRF-protected private IPs.

- **Interactive Visualizations**:
  - 2D Canvas force-directed threat graph with draggable nodes.
  - MITRE ATT&CK Matrix tab with mapped enterprise tactics.
  - Defense Rules Generator tab with copyable rules for iptables, Cisco ASA, AWS WAF, PowerShell, and DNS sinkholes.

- **AI Chat & Export**:
  - Conversational SOC chat assistant grounded in the current scan data.
  - One-click "Draft SOC Ticket" button that produces a formatted markdown ticket.
  - One-click PDF, JSON, and CSV export buttons.

---

## ⚙️ Backend Overview

The FastAPI backend handles all core processing:

- **IoC Extraction**: Uses fast regex patterns to parse IPv4, domains, URLs, emails, hashes (MD5, SHA1, SHA256), and CVE IDs.
- **SSRF Filter**: Validates all IP addresses against RFC 1918 and loopback subnets before any external request can be made.
- **Rate Limiting**: Enforces the VirusTotal public quota of 4 requests/minute using an in-memory token bucket.
- **TTL Cache**: Keeps lookup results in memory for 1 hour so repeat scans are instantaneous.
- **Risk Aggregation**: Runs the mathematical 0–100 scoring model and enforces the anti-dilution floor rule.
- **Multi-Provider AI Client**: Formats prompts safely, sends inference calls to Gemini, Claude, GPT, or partner models, and returns structured mitigation guidance.
- **Static Asset Serving**: Serves the frontend application, manifest, and icons directly with proper MIME types.

---

## 🔌 API Endpoints

| Method | Endpoint | Description | Rate Limit |
|---|---|---|---|
| `GET` | `/` | Serves the main PWA application (`index.html`) | Unlimited |
| `GET` | `/index.html` | Root alias serving the application shell | Unlimited |
| `GET` | `/api/health` | System health check and API key status | 120 / min |
| `POST` | `/api/scan` | Runs full threat scan: extracts IoCs, filters SSRF, queries feeds, calculates score, and generates AI summary | 20 / min |
| `GET` | `/api/demo` | Returns pre-compiled realistic demo results (`?sample=phishing\|mixed\|clean`) | 60 / min |
| `POST` | `/api/chat` | Asks follow-up questions to the AI analyst based on the active scan | 30 / min |
| `GET` | `/serviceworker.js` | Serves the PWA service worker with root scope | Unlimited |
| `GET` | `/manifest.json` | Serves the Web App Manifest | Unlimited |
| `GET` | `/icon192.png` | Serves the 192px cyber shield icon | Unlimited |
| `GET` | `/icon512.png` | Serves the 512px cyber shield icon | Unlimited |
| `GET` | `/frontend/{file}` | Serves static assets requested via frontend subpath | Unlimited |

---

## 🔒 Security Considerations

| Feature | How Threat Z Lens Protects You |
|:---|:---|
| **SSRF Prevention** | Threat Z Lens **never fetches, pings, or opens user-submitted URLs or domains**. All network lookups go strictly to official threat intelligence APIs. Private RFC 1918 subnets and loopback addresses are automatically quarantined. |
| **Prompt Injection Protection** | Threat data sent to the AI is delimited with `<<< >>>` blocks and constrained by a strict SOC analyst system prompt. The model is forced to output structured JSON only. |
| **Client-Side Key Privacy (BYOK)** | API keys entered in the frontend modal stay entirely inside your browser's `localStorage`. They are sent via request headers on demand and are never stored on a server or database. |
| **Secret Masking** | All API keys are masked in startup logs and health check outputs (e.g., `AQ.A...DrOA`), preventing accidental leakage in console logs or screenshots. |
| **Security Headers** | Built-in middleware injects standard security headers: `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `Referrer-Policy: strict-origin-when-cross-origin`. |
| **Rate Limit Protection** | Built-in token-bucket rate limiter ensures you never exceed VirusTotal's public limit of 4 requests/minute. SlowAPI limits protect API routes against spam. |
| **XSS Defense** | The frontend uses safe DOM APIs (`textContent`, `createElement`) to render untrusted values. Indicator strings are never injected through raw `innerHTML`. |
| **Payload Limits** | Uploads are capped at 2 MB and text payloads at 100,000 characters to prevent memory exhaustion. |

---

## 🛠️ Local Setup

Getting Threat Z Lens running locally takes less than 2 minutes:

### 1. Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/Threat-Lens.git
cd Threat-Lens
```

### 2. Create and Activate a Virtual Environment

**On Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**On Linux / macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Requirements

```bash
pip install -r backend/requirements.txt
```

### 4. Create Your `.env` File

Create a `.env` file in the project root:

```env
PORT=8000
ALLOWED_ORIGINS=http://localhost:8000,http://127.0.0.1:8000,http://localhost:5500,http://127.0.0.1:5500

# Optional API Keys (Leave blank to use Demo Mode automatically)
VIRUSTOTAL_API_KEY=your_virustotal_key_here
OTX_API_KEY=your_otx_key_here
GEMINI_API_KEY=your_gemini_key_here

CACHE_TTL_SECONDS=3600
VT_RATE_LIMIT_PER_MINUTE=4
MAX_IOCS_PER_SCAN=15
```

*(Note: If you leave the API keys blank, Threat Z Lens automatically runs in **Demo Mode**, so you can test all features with realistic simulated intelligence without signing up for anything).*

### 5. Run the Tests

Make sure all 18 unit and integration tests pass:

```bash
pytest tests/test_threatlens.py
```

### 6. Start Threat Z Lens

Run directly with Python:
```bash
python backend/main.py
```

Or start with Uvicorn:
```bash
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

Open your browser at: **`http://localhost:8000`**

---

## 🐳 Running with Docker

Threat Z Lens comes with a multi-stage `DOCKERFILE` for easy container execution:

### Build the Image:
```bash
docker build -t threat-z-lens .
```

### Run the Container:
```bash
docker run -d --name threat-z-lens -p 8000:8000 --env-file .env threat-z-lens
```

Visit **`http://localhost:8000`** in your browser.

---

## 🚀 Production Container & Cloud Deployment

Threat Z Lens is designed for seamless containerized deployment across modern cloud platforms and enterprise environments:

`	ext
Source Repository
       ↓
Cloud Host / Enterprise Server
       ↓
Production Docker Container
       ↓
FastAPI High-Performance ASGI
       ↓
Threat Z Lens Command Center Live
`

### Steps to Deploy:
1. Push your repository to your Git provider.
2. Connect your repository to your preferred cloud host or server environment.
3. Set the runtime or build environment to **Docker** (the included production DOCKERFILE builds automatically).
4. In **Environment Variables**, configure:
   - PORT: 8000 (or allow the host platform to bind dynamically)
   - CACHE_TTL_SECONDS: 3600
   - VT_RATE_LIMIT_PER_MINUTE: 4
   - MAX_IOCS_PER_SCAN: 15
   - *(Optional)* VIRUSTOTAL_API_KEY, OTX_API_KEY, GEMINI_API_KEY
5. Click **Deploy**. Threat Z Lens will build the non-root hardened container and start serving immediately.
---

## 🎯 2-Minute Quick Demo Walkthrough

If you want to quickly demonstrate Threat Z Lens to someone, here is the fastest flow:

```text
1. Open https://threat-z-lens.onrender.com/ (or http://localhost:8000 for local dev)
   └─ Show the dark cyber command UI, live UTC Zulu clock, audio toggle (M),
      and active AI model pill.

2. Load Phishing Sample & Show SSRF Quarantine
   └─ Click the "Phishing Lure (Defanged)" button.
   └─ Show the Live Indicator Stream pill bar lighting up in real time.
   └─ Click "Scan Threats" (Ctrl+Enter): Hear the audio scan sweep and watch 
      the extraction, feed querying, and AI summary stages complete.

3. Review the Verdict & Mathematical Score
   └─ Point out the Verdict Banner: Overall Score 88/100 (MALICIOUS).
   └─ Show the 3 circular gauges: Risk, Malicious Ratio, and Evidence Confidence.
   └─ Open the Skipped Indicators drawer to show how internal IP 192.168.1.105 
      was automatically quarantined for SSRF defense.

4. Explore Attack Chain & MITRE Matrix
   └─ Click "Threat Graph": Drag nodes around the 2D Canvas force graph to show 
      how the phishing lure, CVE, and C2 connect with flowing packet particles.
   └─ Click "MITRE ATT&CK": Show how the detected threats map directly to 
      enterprise techniques (T1566, T1204, T1203, T1071).

5. Generate Firewall Rules & Incident Ticket
   └─ Click "Defense Rules": Show one-click generated rules for iptables, Cisco ASA, 
      AWS WAF, and Windows Defender PowerShell.
   └─ In the AI Chat box: Click "Draft SOC Ticket" to generate a ready-to-use 
      markdown incident report ticket.

6. Install PWA & Export
   └─ Click "Export PDF" to generate a printable executive summary.
   └─ Click "Install App" in the header to install Threat Z Lens as a desktop app.
```

---

## ⚠️ Current Limitations

Threat Z Lens is an assistive intelligence tool designed to augment human analysts:

- **Free Public API Tier Limits**: The free VirusTotal API is limited to 4 requests per minute. Threat Z Lens uses an in-memory token bucket limiter and 1-hour caching to prevent rate-limit errors, but high-volume enterprise workloads should use commercial API keys.
- **In-Memory State**: Cache entries and rate limits are stored in server memory. For horizontal clustering across multiple cloud servers, a shared Redis instance should be added.
- **Assistive AI Role**: Threat intelligence summaries generated by AI are assistive guidance and should always be corroborated by trained human analysts during active containment operations.

---

## 🗺️ What I Want to Build Next

Here are some features I'm planning to add in future updates:

- 🛰️ **STIX 2.1 & TAXII 2.1 Feeds**: Direct export and subscription to open threat intelligence sharing platforms (like MISP and OpenCTI).
- 🧠 **Automatic YARA & Sigma Rule Generation**: Generating custom endpoint detection rules directly from scanned malware hashes and C2 behavior.
- 📦 **Redis Caching Layer**: Multi-node distributed caching for large teams.
- 🏢 **SIEM Webhooks**: One-click dispatch of blocklist rules into Splunk, Microsoft Sentinel, and CrowdStrike.
- 🔍 **Historical WHOIS & Passive DNS**: Visualizing domain ownership history and infrastructure shifts over time.

---

## 💡 Project Philosophy

I built Threat Z Lens around one simple idea:

> **"Never trust an indicator just because it hasn't made headlines yet. Do not visit dangerous destinations to find out what they do. Correlate global threat feeds, calculate mathematical risk, and see the threat before it strikes."**

Bring the data together, protect the perimeter, explain the risk with clear math, and give analysts the tools they need to act fast.

---

## ⚖️ Disclaimer

Threat Z Lens is an educational and defensive cybersecurity research tool created for authorized security operations, threat triage, and demonstration.

It is designed for defensive analysis and does not perform active scanning or offensive exploitation. Always ensure you have appropriate authorization before analyzing network telemetry or files.

---

## 👤 Author & License

- **Author / Creator**: **Zidaan** (`Project by : Zidaan`)
- **License**: **MIT License** — Open-source and free for cybersecurity researchers, analysts, and students.
<!-- End of Program (Program by Zidaan) -->
