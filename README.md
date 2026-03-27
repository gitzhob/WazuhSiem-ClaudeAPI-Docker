# Wazuh + LLM Security Triage

An AI-augmented security monitoring system that pairs [Wazuh SIEM](https://wazuh.com/) with Anthropic's Claude API for automated alert triage and proactive threat hunting. The system operates in two modes: **reactive triage** (individual high-severity alerts analyzed in real time) and **proactive hunting** (batch analysis of low-to-medium severity events to find attack patterns no single alert would reveal). All results are written to OpenSearch for review in the Wazuh Dashboard.

### Key Features

- **Automated Alert Triage** — Claude analyzes every high-severity alert with severity rating, root cause, MITRE ATT&CK mapping, and false positive estimation
- **Proactive Threat Hunting** — Batch analysis of hundreds of events to find multi-step attack chains, lateral movement, and persistence mechanisms
- **20 Custom Detection Rules** — Sysmon-powered rules for encoded PowerShell, LOLBin abuse, process masquerading, registry persistence, and more
- **Threat Intelligence IOCs** — ChromaDB-backed indicator of compromise database injected into Claude's analysis context
- **Detection-as-Code** — Claude suggests new Wazuh XML rules when it finds patterns that existing rules miss
- **Structured Output** — Typed JSON via Anthropic's `tool_use` (not free text), enabling programmatic evaluation
- **Evaluation Framework** — Labeled dataset with ground-truth scoring for severity accuracy, MITRE F1, and benign detection
- **RAG Context** — Historical alert memory via ChromaDB gives Claude environment-specific context
- **Human Feedback Loop** — Analysts mark results as agree/disagree, corrections export as new ground truth
- **Cost & Latency Metrics** — Per-call token tracking, USD cost estimation, and quality signal monitoring
- **Experiment Tracking** — Systematic prompt engineering with reproducible comparison tables

## Architecture

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│ Windows Endpoint │     │  Wazuh Manager   │     │  Wazuh Indexer   │
│  + Wazuh Agent   │────▶│  + Custom Rules  │────▶│  (OpenSearch)    │
│  + Sysmon        │1514 │  (threat_hunting │     │  wazuh-alerts-*  │
│                  │     │   .xml, 20 rules)│     │                  │
└──────────────────┘     └──────────────────┘     └──────┬───────────┘
                                                         │
                              ┌───────────────────────────┤
                              │                           │
                       poll every 30s              batch query (hunt)
                              │                           │
                              ▼                           ▼
                    ┌──────────────────┐       ┌──────────────────┐
                    │  Reactive Triage │       │  Proactive Hunt  │
                    │  (triage_service │       │  (hunt.py)       │
                    │   .py)           │       │  5 focus areas   │
                    └────────┬─────────┘       └────────┬─────────┘
                             │                          │
                             ▼                          ▼
                    ┌──────────────────────────────────────────────┐
                    │              Claude API (Anthropic)          │
                    │  structured JSON via tool_use                │
                    │  + RAG context (ChromaDB)                    │
                    │  + Threat Intel IOCs                         │
                    │  + Cost/latency metrics                      │
                    └──────────────────┬──────────────────────────-┘
                                       │
              ┌────────────────────────-┼─────────────────────────┐
              ▼                         ▼                         ▼
    ┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
    │  wazuh-llm-      │     │  wazuh-llm-      │     │  wazuh-llm-      │
    │  triage (index)  │     │  hunts (index)   │     │  feedback (index) │
    │  per-alert       │     │  batch findings  │     │  analyst verdicts│
    │  analysis        │     │  + suggested     │     │  + corrections   │
    │                  │     │    detection rules│     │                  │
    └──────────────────┘     └──────────────────┘     └──────────────────┘
              │                         │                         │
              └─────────────────────────┼─────────────────────────┘
                                        ▼
                              ┌──────────────────┐
                              │  Wazuh Dashboard │
                              │  (view all       │
                              │   results)       │
                              └──────────────────┘
```

## ML Engineering Features

This project goes beyond a basic API integration to demonstrate core ML engineering practices:

**Structured Output via Tool Use** — Claude returns typed JSON (not free text) using Anthropic's `tool_use` feature. Every triage has consistent fields: severity enum, confidence float, MITRE technique objects, benign boolean flags. This enables programmatic evaluation and metric computation. See `llm-triage/schemas.py`.

**Evaluation Framework** — A labeled dataset of 10 security alerts with ground-truth severity, false positive likelihood, MITRE mappings, and benign/malicious classification. The eval runner (`llm-triage/eval/evaluate.py`) scores Claude's output against ground truth and computes accuracy, within-1 agreement, MITRE F1 scores, and benign detection rates. This is the foundation for measuring whether prompt changes actually improve performance.

**Experiment Tracking** — Systematic prompt engineering with full reproducibility. Define prompt variants (few-shot examples, persona changes, format constraints), run each against the eval dataset, and compare results in a structured table. Every experiment is saved with its prompt hash, model, scores, cost, and latency. See `notebooks/experiment_tracking.py`.

**Cost & Latency Monitoring** — Per-call tracking of input/output tokens, estimated USD cost (by model), response latency, and quality signals (severity distribution, confidence stats). Aggregate metrics are logged periodically and available programmatically. See `llm-triage/metrics.py`.

**Human-in-the-Loop Feedback** — Analysts can mark triage results as "agree," "disagree," or "partial" with optional severity/FP corrections. Feedback is stored in OpenSearch (`wazuh-llm-feedback` index) and can be exported as new evaluation dataset entries — closing the loop between model output and human ground truth. See `llm-triage/feedback.py`.

**RAG Context Injection** — Optional retrieval-augmented generation using ChromaDB. Past alerts and their triage outcomes are embedded and stored locally. When a new alert arrives, similar historical alerts are retrieved and injected into the prompt, giving Claude environment-specific context like "this IP was flagged 3 times last week and confirmed benign." See `llm-triage/rag.py`.

## Tech Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| SIEM | Wazuh 4.12.0 | Security event collection, rule-based detection |
| Endpoint Telemetry | Sysmon | Process creation, network, file, registry, DNS events |
| Data Store | OpenSearch (via Wazuh Indexer) | Alert storage, triage results, hunt findings, feedback |
| Web UI | Wazuh Dashboard | Visualization of alerts, triage, and hunt results |
| AI Engine | Claude Sonnet/Opus 4.6 (Anthropic API) | Structured analysis via tool_use |
| Triage Service | Python 3.12 | Reactive alert triage with metrics and RAG |
| Hunt Service | Python 3.12 | Proactive batch event analysis across 5 focus areas |
| Threat Intel | Python 3.12 + ChromaDB | IOC management and context injection |
| Vector DB | ChromaDB | RAG similarity search + IOC storage |
| Infrastructure | Docker Compose | Single-node deployment of all services |

## Project Structure

```
wazuh-llm-security/
├── docker-compose.yml              # Full stack: Manager, Indexer, Dashboard, LLM Triage
├── generate-indexer-certs.yml       # One-shot TLS certificate generator
├── .env.example                     # Template for secrets and configuration
├── .gitignore                       # Excludes .env, certs, volumes, Python artifacts
│
├── config/
│   ├── certs.yml                    # Node definitions for TLS cert generation
│   ├── sysmon/
│   │   └── sysmonconfig.xml         # Sysmon config for endpoint telemetry
│   ├── wazuh_cluster/
│   │   ├── wazuh_manager.conf       # Wazuh Manager ossec.conf
│   │   └── rules/
│   │       └── threat_hunting.xml   # Custom detection rules (level 8-14)
│   ├── wazuh_indexer/
│   │   ├── wazuh.indexer.yml        # OpenSearch configuration
│   │   └── internal_users.yml       # OpenSearch user definitions
│   └── wazuh_dashboard/
│       ├── opensearch_dashboards.yml
│       └── wazuh.yml
│
├── llm-triage/
│   ├── Dockerfile                   # Python 3.12-slim, non-root user
│   ├── requirements.txt             # anthropic, requests, chromadb, pandas
│   ├── triage_service.py            # Reactive: poll + triage individual alerts
│   ├── hunt.py                      # Proactive: batch event analysis for threat hunting
│   ├── threat_intel.py              # IOC feed management for RAG context
│   ├── schemas.py                   # Structured output schema (Anthropic tool_use)
│   ├── metrics.py                   # Cost, latency, and quality tracking
│   ├── feedback.py                  # Analyst feedback loop + export
│   ├── rag.py                       # RAG context with ChromaDB
│   ├── prompts/
│   │   ├── triage_system.txt        # Reactive triage prompt (SOC analyst)
│   │   └── hunt_system.txt          # Proactive hunt prompt (threat hunter)
│   └── eval/
│       ├── labeled_dataset.json     # 10 alerts with ground-truth labels
│       └── evaluate.py              # Scoring: accuracy, F1, within-1 agreement
│
└── notebooks/
    └── experiment_tracking.py       # Prompt variant comparison + experiment log
```

## Quick Start

### Prerequisites

- Docker Desktop with WSL2 backend (Windows) or Docker Engine (Linux/macOS)
- An [Anthropic API key](https://console.anthropic.com/settings/keys)
- 8 GB RAM allocated to Docker (WSL2: configure via `~/.wslconfig`)

### 1. Clone and Configure

```bash
git clone https://github.com/gitzhob/WazuhSiem-ClaudeAPI-Docker.git
cd WazuhSiem-ClaudeAPI-Docker
cp .env.example .env
# Edit .env and add your Anthropic API key + set strong passwords
```

### 2. Set vm.max_map_count (Required for OpenSearch)

**Windows (WSL2):**
```powershell
wsl -d Ubuntu -u root -- sysctl -w vm.max_map_count=262144
```

**Linux:**
```bash
sudo sysctl -w vm.max_map_count=262144
```

### 3. Generate TLS Certificates

```bash
docker compose -f generate-indexer-certs.yml run --rm generator
```

### 4. Start the Stack

```bash
docker compose up -d
```

Wait ~60 seconds for initial startup, then access the Wazuh Dashboard at `https://localhost:443` (default credentials: `admin` / `SecretPassword`).

### 5. Install a Wazuh Agent

Download the [Wazuh agent](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/index.html) on the endpoint you want to monitor. Point it at the Wazuh Manager's IP/hostname on port 1514.

### 6. Run a Test Triage (No Live Alerts Needed)

```bash
docker compose run --rm llm-triage python triage_service.py --test
```

This sends 3 sample alerts (SSH brute force, hosts file modification, Domain Admins group change) to Claude and prints structured triage analysis with per-call cost and latency metrics.

### 7. Start Live Polling

```bash
docker compose up -d llm-triage
docker compose logs -f llm-triage
```

The service polls OpenSearch every 30 seconds for new alerts at level 10+, triages them through Claude, and writes structured results to the `wazuh-llm-triage` index.

## Proactive Threat Hunting

The system operates in two modes. **Reactive mode** (triage_service.py) handles individual high-severity alerts in real time. **Hunt mode** (hunt.py) takes a fundamentally different approach — it pulls batches of low-to-medium severity events and asks Claude to analyze them as a group, looking for attack patterns that no single alert would reveal.

### Install Sysmon (Recommended)

Sysmon gives Wazuh process-level visibility — command-line arguments, network connections, DNS queries, and file creation. Without it, Claude can only hunt through Windows Event Logs and file integrity events. With it, Claude can spot encoded PowerShell, LOLBin abuse, suspicious parent-child process chains, and C2 callbacks.

Download [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) from Microsoft, then install with the included config:

```powershell
sysmon64.exe -accepteula -i config\sysmon\sysmonconfig.xml
```

### Run a Threat Hunt

```bash
# General sweep of the last hour
docker compose run --rm llm-triage python hunt.py

# Focus on lateral movement, look back 4 hours
docker compose run --rm llm-triage python hunt.py --focus lateral --hours 4

# Focus areas: general, lateral, persistence, exfiltration, execution
docker compose run --rm llm-triage python hunt.py --focus persistence

# Run continuous hunts every hour
docker compose run --rm llm-triage python hunt.py --continuous
```

Hunt findings are written to the `wazuh-llm-hunts` OpenSearch index and include structured findings with evidence, MITRE ATT&CK mappings, and — when Claude identifies a gap — suggested Wazuh detection rules that would catch the pattern automatically next time.

### Custom Detection Rules

The project includes 20 custom Wazuh rules (`config/wazuh_cluster/rules/threat_hunting.xml`) that fire on Sysmon events indicating common attack techniques: encoded PowerShell, LOLBin abuse (certutil, mshta, rundll32), Office macros spawning shells, process masquerading, executables in suspicious paths, registry persistence, and process tampering.

### Threat Intelligence IOCs

The threat intel module (`threat_intel.py`) manages indicators of compromise that get injected into Claude's context via RAG. When an alert contains a known-bad IP, domain, hash, or command pattern, Claude automatically receives context like "this IP was flagged as a C2 server in our threat feed."

```bash
# Load default IOC set
docker compose run --rm llm-triage python threat_intel.py --load-defaults

# Load custom IOCs from file
docker compose run --rm llm-triage python threat_intel.py --load my_iocs.json

# Check if a value is in the IOC database
docker compose run --rm llm-triage python threat_intel.py --check 203.0.113.42
```

### Detection-as-Code

When Claude identifies a suspicious pattern during a hunt that Wazuh's existing rules don't cover, it generates suggested Wazuh XML rules as part of its findings. This closes the loop: the AI teaches the SIEM what to watch for, so next time the pattern appears it's caught in real time without needing an LLM call.

## Evaluation & Experimentation

### Run the Evaluation Suite

Score Claude's triage against the labeled dataset:

```bash
cd llm-triage
python -m eval.evaluate --verbose
```

Output includes per-alert scoring and aggregate metrics. To compare models, use the `--model` flag:

```bash
python -m eval.evaluate --model claude-opus-4-6 --verbose
```

### Model Comparison: Sonnet 4.6 vs Opus 4.6

Both models were evaluated against the same 10-alert labeled dataset with identical system prompts.

| Metric | Sonnet 4.6 | Opus 4.6 |
|--------|-----------|----------|
| **Severity accuracy** (exact) | 70.0% | **90.0%** |
| **Severity accuracy** (within-1) | 100.0% | 100.0% |
| **False positive accuracy** | 80.0% | **100.0%** |
| **MITRE ATT&CK F1** | **95.0%** | 60.0% |
| **Benign detection** | 90.0% | 90.0% |
| **Avg confidence** | 0.782 | **0.900** |
| **Cost per eval** (10 alerts) | **$0.19** | $0.91 |
| **Avg latency** | **1,240ms** | 16,442ms |

**Key findings:**

Opus 4.6 is substantially better at the two most important triage tasks — correctly rating severity (90% vs 70%) and identifying false positives (100% vs 80%). It also reports higher self-confidence scores that align with its improved accuracy. However, it scored lower on MITRE ATT&CK technique identification (60% vs 95% F1), suggesting it may be more selective about which techniques it maps rather than matching Wazuh's broader tagging.

The trade-off is cost and speed: Opus costs ~5x more per alert ($0.09 vs $0.02) and takes ~13x longer (16s vs 1.2s). For production use with a small alert volume, Opus may be worth the premium. For high-volume environments, Sonnet provides strong accuracy at a fraction of the cost, with the option to escalate ambiguous cases to Opus.

### Understanding Ground Truth and Scoring

The evaluation framework scores Claude's triage output against **ground truth** — human-determined correct answers for each alert. The included dataset (`llm-triage/eval/labeled_dataset.json`) contains 10 alerts with labels I assigned manually based on security domain knowledge: the expected severity, false positive likelihood, MITRE ATT&CK techniques, and whether the root cause is benign or malicious.

**Important:** These labels are a starting point, not gospel. If you deploy this in your own environment, you should review and adjust the ground truth labels to match your security posture and operational context. What counts as "CRITICAL" in a small business may only be "HIGH" in an enterprise with layered defenses. The evaluation is only as good as the human labels it scores against.

The recommended workflow for building accurate ground truth over time:

1. Start with the included dataset to get baseline scores
2. Run the triage service in production and have analysts review results
3. Use the feedback loop (`feedback.py`) to mark Claude's assessments as agree/disagree with corrections
4. Export analyst feedback as new evaluation entries: the `FeedbackStore.export_as_eval_dataset()` method converts corrections into ground truth format
5. Re-run the eval suite to measure whether prompt changes or model upgrades actually improve accuracy against your real-world labels

The RAG system (`rag.py`) also benefits from this cycle — as more alerts are triaged and verified by analysts, ChromaDB accumulates environment-specific context. When a new alert resembles one that was previously reviewed, that historical context is injected into Claude's prompt, improving accuracy for your specific infrastructure over time.

### Run Prompt Experiments

Compare different prompt strategies:

```bash
cd notebooks

# Run baseline
python experiment_tracking.py --experiment baseline

# Try few-shot examples
python experiment_tracking.py --experiment few-shot

# Try threat-hunter persona
python experiment_tracking.py --experiment threat-hunter

# Run all variants and compare
python experiment_tracking.py --all

# View comparison table
python experiment_tracking.py --compare
```

## Configuration

All configuration is in `.env`:

| Variable | Default | Description |
|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | — | Your Anthropic API key (required) |
| `CLAUDE_MODEL` | `claude-sonnet-4-6` | Claude model for triage |
| `ALERT_LEVEL_THRESHOLD` | `10` | Minimum Wazuh rule level to triage (1-15) |
| `POLL_INTERVAL_SECONDS` | `30` | How often to check for new alerts |
| `RAG_ENABLED` | `false` | Enable ChromaDB context injection |

### OpenSearch Indices

The system writes to three custom indices (in addition to Wazuh's built-in `wazuh-alerts-*`):

| Index | Written By | Contains |
|-------|-----------|----------|
| `wazuh-llm-triage` | triage_service.py | Per-alert structured triage (severity, confidence, MITRE, actions) |
| `wazuh-llm-hunts` | hunt.py | Batch hunt findings, evidence, suggested detection rules |
| `wazuh-llm-feedback` | feedback.py | Analyst verdicts (agree/disagree/partial) with corrections |

### Cost Estimates

- **Claude Sonnet 4.6**: ~$0.01-0.02 per alert (recommended for production)
- **Claude Opus 4.6**: ~$0.05-0.10 per alert (deeper analysis, higher cost)
- **Full eval suite** (10 alerts): ~$0.15-0.20 with Sonnet

At threshold 10+, most environments generate a handful of high-severity alerts per day, keeping costs well under $1/day.

## Viewing Results in the Dashboard

All triage results, hunt findings, and analyst feedback are stored in OpenSearch and viewable in the Wazuh Dashboard at `https://localhost`.

### Setting Up Index Patterns

To view LLM results in the dashboard, create index patterns for each data type:

1. Open the Wazuh Dashboard and click the hamburger menu (top left)
2. Go to **Dashboard Management** → **Index Patterns** → **Create index pattern**
3. Create patterns for each index:

| Index Pattern | Contains |
|--------------|----------|
| `wazuh-llm-triage*` | Per-alert triage results (severity, confidence, MITRE, actions) |
| `wazuh-llm-hunts*` | Threat hunt findings (batch analysis, suggested rules) |
| `wazuh-llm-feedback*` | Analyst feedback (agree/disagree verdicts, corrections) |

4. Select `timestamp` as the time field for each pattern
5. Go to **Discover** (from the hamburger menu), select your index pattern, and set the time range to "Last 24 hours"

You can filter by severity, confidence, MITRE technique, or any other structured field. Each document represents one complete analysis from Claude with all fields available for search and visualization.

## Sample Structured Output

Claude returns typed JSON via Anthropic's `tool_use` feature:

```json
{
  "severity": "LOW",
  "confidence": 0.92,
  "summary": "The W32Time service updated its SecureTimeLimits registry key during a routine NTP sync cycle.",
  "likely_cause": [
    {"explanation": "Routine NTP sync updates SecureTimeHigh/Low values automatically.", "benign": true},
    {"explanation": "Manual system clock adjustment by an admin.", "benign": true}
  ],
  "actions": [
    "Correlate with Windows Event ID 37 to confirm NTP sync.",
    "Verify no unexpected clock drift: w32tm /query /status",
    "Suppress via Wazuh rule tuning if confirmed routine."
  ],
  "mitre_attack": [
    {"technique_id": "T1112", "technique_name": "Modify Registry"}
  ],
  "false_positive_likelihood": "HIGH",
  "false_positive_reasoning": "SecureTimeHigh is updated automatically by W32Time during every NTP sync.",
  "related_alerts": "Windows Event IDs 35, 37 (W32Time); Wazuh rule 750",
}
```

## Getting Started (Non-Technical Guide)

New to security tools or Docker? This section walks you through the basics.

### What Does This Tool Do?

Think of it like a smart security camera system for your computer. Wazuh is the camera — it watches everything happening on your machine (logins, file changes, programs running, network connections). When something looks suspicious, it creates an alert. The problem is, security systems create *hundreds* of alerts per day, and most of them are harmless. That's where Claude comes in.

Claude acts like a security analyst on your team who reads every single alert and tells you: "This one is harmless — Windows was just updating itself" or "This one is serious — someone may be trying to access accounts they shouldn't." It does this automatically, 24/7, in seconds.

### What You Need Before Starting

1. **Docker Desktop** — This is the app that runs everything. Download it free from [docker.com](https://www.docker.com/products/docker-desktop/). Install it, open it, and make sure it says "Running" in the bottom left.

2. **An Anthropic API Key** — This is like a password that lets the tool talk to Claude. Go to [console.anthropic.com](https://console.anthropic.com/settings/keys), create an account, and generate a key. It starts with `sk-ant-`. You'll need to add billing (the tool costs roughly 1-2 cents per alert analyzed).

3. **8 GB of RAM for Docker** — On Windows, open a text editor and create a file at `C:\Users\YourName\.wslconfig` with these lines, then restart Docker Desktop:
   ```
   [wsl2]
   memory=8GB
   ```

### Step-by-Step Setup

**Step 1 — Download the project.** Open PowerShell (search for it in the Start menu) and type:
```
git clone https://github.com/gitzhob/WazuhSiem-ClaudeAPI-Docker.git
cd WazuhSiem-ClaudeAPI-Docker
```

**Step 2 — Add your API key.** In the project folder, copy the file `.env.example` and rename the copy to `.env`. Open `.env` in Notepad and replace the placeholder API key with your real one. Save and close.

**Step 3 — Set up OpenSearch.** This is a one-time command. In PowerShell:
```
wsl -d Ubuntu -u root -- sysctl -w vm.max_map_count=262144
```

**Step 4 — Generate security certificates.** In PowerShell:
```
docker compose -f generate-indexer-certs.yml run --rm generator
```

**Step 5 — Start everything.** In PowerShell:
```
docker compose up -d
```
Wait about 60 seconds. Five containers will start — you'll see green "Running" next to each.

**Step 6 — Open the dashboard.** Go to `https://localhost` in your browser. You'll get a security warning — that's normal, click "Advanced" then "Proceed." Log in with username `admin` and password `SecretPassword`.

### Daily Use

Once everything is running, you don't need to do much. The tool works automatically in the background. Here are the things you might want to do:

**Check on triage results** — Open the Wazuh Dashboard at `https://localhost`, go to **Discover**, and select the `wazuh-llm-triage*` index pattern. You'll see every alert Claude has analyzed with severity ratings, explanations, and recommended actions. See the [Viewing Results in the Dashboard](#viewing-results-in-the-dashboard) section above for setup.

**Run a threat hunt** — This asks Claude to review a batch of recent events and look for hidden attack patterns. Think of it like asking a detective to review all the security camera footage from the last day, instead of just responding to alarms. In PowerShell:
```
docker compose run --rm llm-triage python hunt.py --hours 24
```
You can focus the hunt on specific attack types like `--focus lateral` (hackers moving between machines), `--focus persistence` (hackers setting up backdoors), or `--focus exfiltration` (data being stolen).

**Load threat intelligence** — This teaches the system about known bad IPs, domains, and file hashes so Claude can flag them instantly:
```
docker compose run --rm llm-triage python threat_intel.py --load-defaults
```

**View hunt findings** — In the Wazuh Dashboard, select the `wazuh-llm-hunts*` index pattern in Discover. Each hunt result shows what Claude found, what evidence it used, and what MITRE ATT&CK techniques it identified.

**Stop the tool** (to save resources or API costs):
```
docker compose stop
```

**Start it back up:**
```
docker compose up -d
```

**Stop only the AI analysis** (keep monitoring active but don't spend API credits):
```
docker compose stop llm-triage
```

### What the Severity Levels Mean

When Claude analyzes an alert, it assigns one of four severity levels:

- **CRITICAL** — Immediate attention needed. Something is actively being exploited or compromised. Example: someone disabled your antivirus remotely.
- **HIGH** — Investigate soon. A known attack technique was detected but may not have succeeded yet. Example: repeated failed login attempts from an unknown IP.
- **MEDIUM** — Worth reviewing. Unusual activity that could be suspicious or could be a normal admin task. Example: a new program was added to startup.
- **LOW** — Probably harmless. Routine system activity that triggered a rule. Example: Windows updated a registry key during a normal update cycle.

### Troubleshooting

- **"Fetched 0 alerts"** — The tool is running but no new security events match the threshold. This is normal if your machine has been idle. Lower the `ALERT_LEVEL_THRESHOLD` in `.env` to `5` to see more results.
- **Dashboard won't load** — Make sure Docker Desktop is running and all containers show "Running." Try `docker compose restart` in PowerShell.
- **API errors** — Check that your Anthropic API key in `.env` is correct and your account has billing set up.

## Stopping and Restarting

```bash
# Stop everything (preserves data)
docker compose stop

# Start everything back up
docker compose up -d

# Stop only the triage service (to save API costs when not needed)
docker compose stop llm-triage
```

## License

The Wazuh components are licensed under [GPLv2](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html). The LLM triage service code in `llm-triage/` is MIT licensed.
