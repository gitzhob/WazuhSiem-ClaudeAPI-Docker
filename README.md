# Wazuh + LLM Security Triage

An AI-augmented security monitoring system that pairs [Wazuh SIEM](https://wazuh.com/) with Anthropic's Claude API for automated alert triage. When Wazuh detects a high-severity security event on a monitored endpoint, the LLM triage service sends the raw alert to Claude for instant analysis — severity assessment, likely root cause, recommended actions, MITRE ATT&CK mapping, and false positive estimation — then writes the enriched result back to OpenSearch for review in the Wazuh Dashboard.

## Architecture

```
┌──────────────┐       ┌──────────────────┐       ┌──────────────────┐
│   Windows    │       │  Wazuh Manager   │       │  Wazuh Indexer   │
│   Endpoint   │──────▶│  (event parsing  │──────▶│  (OpenSearch)    │
│  w/ Wazuh    │ 1514  │   & rule engine) │       │  stores alerts   │
│   Agent      │       │                  │       │  in wazuh-alerts │
└──────────────┘       └──────────────────┘       └────────┬─────────┘
                                                           │
                                                           │ poll every 30s
                                                           ▼
┌──────────────┐       ┌──────────────────┐       ┌──────────────────┐
│    Wazuh     │       │  Claude API      │       │  LLM Triage      │
│  Dashboard   │◀──────│  (Anthropic)     │◀──────│  Service         │
│  view triage │  read │  AI analysis     │       │  (Python)        │
│  results     │       │                  │       │                  │
└──────────────┘       └──────────────────┘       └──────────────────┘
```

The triage service queries the `wazuh-alerts-*` OpenSearch index for alerts at or above a configurable severity threshold (default: rule level 10+). New alerts are sent to Claude with a structured SOC analyst prompt. Claude returns a standardized triage report that gets indexed into `wazuh-llm-triage` for review alongside the original alerts.

## What the AI Triage Provides

Each alert sent to Claude returns a structured analysis:

- **Severity rating** (Critical / High / Medium / Low) based on actual threat level, not just Wazuh's rule number
- **Plain-English summary** of what happened
- **Likely cause** ranked by probability, noting whether it's likely benign or malicious
- **Recommended actions** with specific commands, queries, and file paths
- **MITRE ATT&CK mapping** for threat intelligence context
- **False positive likelihood** so analysts can prioritize effectively
- **Related alerts** to correlate with for fuller picture

## Tech Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| SIEM | Wazuh 4.12.0 | Security event collection, rule-based detection |
| Data Store | OpenSearch (via Wazuh Indexer) | Alert storage, search, and enriched triage results |
| Web UI | Wazuh Dashboard | Alert visualization and triage review |
| AI Engine | Claude Sonnet 4.6 (Anthropic API) | Automated alert analysis and triage |
| Triage Service | Python 3.12 | Orchestration between OpenSearch and Claude |
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
│   ├── wazuh_cluster/
│   │   └── wazuh_manager.conf       # Wazuh Manager ossec.conf
│   ├── wazuh_indexer/
│   │   ├── wazuh.indexer.yml        # OpenSearch configuration
│   │   └── internal_users.yml       # OpenSearch user definitions
│   └── wazuh_dashboard/
│       ├── opensearch_dashboards.yml
│       └── wazuh.yml
│
└── llm-triage/
    ├── Dockerfile                   # Python 3.12-slim, non-root user
    ├── requirements.txt             # anthropic, requests, python-dotenv
    ├── triage_service.py            # Main service: polling, triage, indexing
    └── prompts/
        └── triage_system.txt        # Claude system prompt (SOC analyst role)
```

## Quick Start

### Prerequisites

- Docker Desktop with WSL2 backend (Windows) or Docker Engine (Linux/macOS)
- An [Anthropic API key](https://console.anthropic.com/settings/keys)
- 8 GB RAM allocated to Docker (WSL2: configure via `~/.wslconfig`)

### 1. Clone and Configure

```bash
git clone https://github.com/YOUR_USERNAME/wazuh-llm-security.git
cd wazuh-llm-security
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

This sends 3 sample alerts (SSH brute force, hosts file modification, Domain Admins group change) to Claude and prints the triage analysis. Useful for verifying your API key works before going live.

### 7. Start Live Polling

```bash
docker compose up -d llm-triage
docker compose logs -f llm-triage
```

The service polls OpenSearch every 30 seconds for new alerts at level 10+, triages them through Claude, and writes results to the `wazuh-llm-triage` index.

## Configuration

All configuration is in `.env`:

| Variable | Default | Description |
|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | — | Your Anthropic API key (required) |
| `CLAUDE_MODEL` | `claude-sonnet-4-6` | Claude model for triage (`claude-sonnet-4-6` or `claude-opus-4-6`) |
| `ALERT_LEVEL_THRESHOLD` | `10` | Minimum Wazuh rule level to triage (1-15) |
| `POLL_INTERVAL_SECONDS` | `30` | How often to check for new alerts |

### Cost Estimates

- **Claude Sonnet 4.6**: ~$0.01-0.02 per alert (recommended for production)
- **Claude Opus 4.6**: ~$0.05-0.10 per alert (deeper analysis, higher cost)

At threshold 10+, most environments generate a handful of high-severity alerts per day, keeping costs well under $1/day.

## Customizing the Triage Prompt

The system prompt that shapes Claude's analysis lives in `llm-triage/prompts/triage_system.txt`. You can customize it to fit your environment — add context about your network topology, specify which alerts to treat as known false positives, or adjust the output format.

## Stopping and Restarting

```bash
# Stop everything (preserves data)
docker compose stop

# Start everything back up
docker compose up -d

# Stop only the triage service (to save API costs when not needed)
docker compose stop llm-triage
```

## Sample Output

Here's Claude analyzing a real Windows registry integrity alert:

```
SEVERITY: LOW

SUMMARY: The W32Time service updated its SecureTimeLimits registry key during
a routine NTP synchronization cycle. This is expected system behavior.

LIKELY CAUSE:
1. Routine NTP time synchronization — W32Time updates SecureTimeHigh/Low
   values after each sync cycle (most likely).
2. Manual system clock adjustment by an administrator.

ACTIONS:
1. Correlate with Event ID 37 (W32Time time adjustment) to confirm NTP sync.
2. Verify no unexpected clock drift: w32tm /query /status
3. Suppress this alert via Wazuh rule tuning if confirmed routine.

MITRE ATT&CK: T1112 – Modify Registry (mapping technically correct but
overstates risk here)

FALSE POSITIVE LIKELIHOOD: High — SecureTimeHigh is a dynamic value updated
automatically by the W32Time service during every NTP sync cycle.

RELATED ALERTS: Windows Event IDs 35, 37 (W32Time); Wazuh rule 750 firing
repeatedly in short intervals would warrant escalation.
```

## License

The Wazuh components are licensed under [GPLv2](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html). The LLM triage service code in `llm-triage/` is MIT licensed.
