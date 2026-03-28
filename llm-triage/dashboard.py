"""
Streamlit Dashboard — Wazuh LLM Triage

Real-time monitoring dashboard for the LLM-powered security triage pipeline.
Shows triage results, threat hunts, eval metrics, and cost tracking.

Usage:
    streamlit run dashboard.py
    streamlit run dashboard.py -- --opensearch-url https://localhost:9200

Requires:
    pip install streamlit plotly pandas
"""

import os
import sys
import json
import time
import logging
import argparse
from datetime import datetime, timezone, timedelta
from pathlib import Path

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

# Add parent dir so we can import project modules
sys.path.insert(0, str(Path(__file__).parent))

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Wazuh LLM Triage Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Sidebar — Configuration
# ---------------------------------------------------------------------------
st.sidebar.title("🛡️ LLM Triage")
st.sidebar.markdown("---")

DATA_SOURCE = st.sidebar.radio(
    "Data Source",
    ["OpenSearch (Live)", "JSON File (Upload)", "Demo Data"],
    index=2,
)

OPENSEARCH_URL = st.sidebar.text_input(
    "OpenSearch URL",
    value=os.environ.get("INDEXER_URL", "https://localhost:9200"),
    disabled=DATA_SOURCE != "OpenSearch (Live)",
)

AUTO_REFRESH = st.sidebar.checkbox("Auto-refresh (30s)", value=False)
if AUTO_REFRESH:
    st.sidebar.info("Dashboard refreshes every 30 seconds")
    time.sleep(0.1)  # prevent tight loop

# ---------------------------------------------------------------------------
# Data loading functions
# ---------------------------------------------------------------------------

def generate_demo_data() -> list[dict]:
    """Generate realistic demo triage results for showcase purposes."""
    return [
        {
            "timestamp": "2026-03-28T08:15:00Z",
            "rule_id": "5710",
            "rule_level": 10,
            "rule_description": "sshd: Attempt to login using a denied user",
            "agent_name": "web-server-01",
            "agent_ip": "10.0.1.50",
            "source_ip": "203.0.113.42",
            "severity": "HIGH",
            "confidence": 0.92,
            "false_positive_likelihood": "LOW",
            "summary": "External brute force attack targeting SSH with invalid usernames from known malicious IP range.",
            "recommended_actions": "Block source IP at firewall, review SSH access policies, enable fail2ban.",
            "mitre_techniques": "T1110 - Brute Force",
            "input_tokens": 1150,
            "output_tokens": 380,
            "cost_usd": 0.0092,
            "latency_ms": 2340,
        },
        {
            "timestamp": "2026-03-28T08:22:00Z",
            "rule_id": "550",
            "rule_level": 10,
            "rule_description": "Integrity checksum changed (hosts file)",
            "agent_name": "dev-workstation",
            "agent_ip": "10.0.1.100",
            "source_ip": "",
            "severity": "CRITICAL",
            "confidence": 0.88,
            "false_positive_likelihood": "LOW",
            "summary": "Windows hosts file modified — possible DNS hijacking or malware redirecting traffic.",
            "recommended_actions": "Isolate workstation, compare hosts file to baseline, scan for malware.",
            "mitre_techniques": "T1565.001 - Stored Data Manipulation",
            "input_tokens": 1280,
            "output_tokens": 420,
            "cost_usd": 0.0101,
            "latency_ms": 2780,
        },
        {
            "timestamp": "2026-03-28T09:05:00Z",
            "rule_id": "5501",
            "rule_level": 5,
            "rule_description": "Login session opened",
            "agent_name": "app-server-02",
            "agent_ip": "10.0.1.75",
            "source_ip": "10.0.1.10",
            "severity": "LOW",
            "confidence": 0.95,
            "false_positive_likelihood": "HIGH",
            "summary": "Routine login session from internal admin workstation during business hours.",
            "recommended_actions": "No action needed. Expected administrative activity.",
            "mitre_techniques": "T1078 - Valid Accounts",
            "input_tokens": 980,
            "output_tokens": 290,
            "cost_usd": 0.0073,
            "latency_ms": 1890,
        },
        {
            "timestamp": "2026-03-28T09:30:00Z",
            "rule_id": "100002",
            "rule_level": 12,
            "rule_description": "Suspicious PowerShell execution detected",
            "agent_name": "dev-workstation",
            "agent_ip": "10.0.1.100",
            "source_ip": "",
            "severity": "CRITICAL",
            "confidence": 0.91,
            "false_positive_likelihood": "LOW",
            "summary": "Base64-encoded PowerShell command executed with bypass flags — classic attack pattern.",
            "recommended_actions": "Isolate host immediately, capture memory dump, investigate parent process chain.",
            "mitre_techniques": "T1059.001 - PowerShell, T1027 - Obfuscated Files",
            "input_tokens": 1400,
            "output_tokens": 450,
            "cost_usd": 0.0117,
            "latency_ms": 3100,
        },
        {
            "timestamp": "2026-03-28T10:15:00Z",
            "rule_id": "5715",
            "rule_level": 6,
            "rule_description": "sshd: authentication success",
            "agent_name": "db-server-01",
            "agent_ip": "10.0.1.200",
            "source_ip": "10.0.1.10",
            "severity": "LOW",
            "confidence": 0.97,
            "false_positive_likelihood": "HIGH",
            "summary": "Successful SSH login from internal admin IP. Normal operational access pattern.",
            "recommended_actions": "No action required. Log for audit trail.",
            "mitre_techniques": "T1078 - Valid Accounts",
            "input_tokens": 920,
            "output_tokens": 260,
            "cost_usd": 0.0067,
            "latency_ms": 1650,
        },
        {
            "timestamp": "2026-03-28T10:45:00Z",
            "rule_id": "87924",
            "rule_level": 14,
            "rule_description": "Rootkit detection: hidden process found",
            "agent_name": "web-server-01",
            "agent_ip": "10.0.1.50",
            "source_ip": "",
            "severity": "CRITICAL",
            "confidence": 0.85,
            "false_positive_likelihood": "LOW",
            "summary": "Hidden process detected by rootcheck — possible rootkit or kernel-level compromise.",
            "recommended_actions": "Immediate incident response: isolate server, boot from clean media, forensic image.",
            "mitre_techniques": "T1014 - Rootkit, T1068 - Exploitation for Privilege Escalation",
            "input_tokens": 1350,
            "output_tokens": 410,
            "cost_usd": 0.0109,
            "latency_ms": 2950,
        },
        {
            "timestamp": "2026-03-28T11:00:00Z",
            "rule_id": "5710",
            "rule_level": 10,
            "rule_description": "sshd: Attempt to login using a denied user",
            "agent_name": "app-server-02",
            "agent_ip": "10.0.1.75",
            "source_ip": "198.51.100.23",
            "severity": "MEDIUM",
            "confidence": 0.89,
            "false_positive_likelihood": "MEDIUM",
            "summary": "Single failed SSH attempt from external IP. Could be scan noise or targeted probe.",
            "recommended_actions": "Monitor for repeat attempts from this IP. Add to watchlist if pattern continues.",
            "mitre_techniques": "T1110 - Brute Force",
            "input_tokens": 1100,
            "output_tokens": 340,
            "cost_usd": 0.0084,
            "latency_ms": 2200,
        },
        {
            "timestamp": "2026-03-28T11:30:00Z",
            "rule_id": "60106",
            "rule_level": 8,
            "rule_description": "Large number of files deleted",
            "agent_name": "file-server-01",
            "agent_ip": "10.0.1.150",
            "source_ip": "",
            "severity": "HIGH",
            "confidence": 0.86,
            "false_positive_likelihood": "MEDIUM",
            "summary": "Bulk file deletion detected — could be ransomware preparation or unauthorized cleanup.",
            "recommended_actions": "Verify with file owner, check for encryption activity, review backup status.",
            "mitre_techniques": "T1485 - Data Destruction, T1486 - Data Encrypted for Impact",
            "input_tokens": 1200,
            "output_tokens": 370,
            "cost_usd": 0.0091,
            "latency_ms": 2500,
        },
    ]


def load_from_opensearch(url: str) -> list[dict]:
    """Load triage results from OpenSearch llm-triage-results index."""
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    username = os.environ.get("INDEXER_USERNAME", "admin")
    password = os.environ.get("INDEXER_PASSWORD", "")

    try:
        resp = requests.get(
            f"{url}/llm-triage-results/_search",
            json={"size": 200, "sort": [{"timestamp": {"order": "desc"}}]},
            auth=(username, password),
            verify=False,
            timeout=10,
        )
        resp.raise_for_status()
        hits = resp.json().get("hits", {}).get("hits", [])
        return [h["_source"] for h in hits]
    except Exception as e:
        st.error(f"Failed to connect to OpenSearch: {e}")
        return []


def load_data(source: str) -> pd.DataFrame:
    """Load triage data from the selected source and return a DataFrame."""
    if source == "Demo Data":
        records = generate_demo_data()
    elif source == "OpenSearch (Live)":
        records = load_from_opensearch(OPENSEARCH_URL)
    elif source == "JSON File (Upload)":
        uploaded = st.sidebar.file_uploader("Upload triage results JSON", type=["json"])
        if uploaded:
            records = json.load(uploaded)
            if isinstance(records, dict):
                records = records.get("results", [records])
        else:
            st.info("Upload a JSON file with triage results to get started.")
            return pd.DataFrame()
    else:
        records = []

    if not records:
        return pd.DataFrame()

    df = pd.DataFrame(records)
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df


# ---------------------------------------------------------------------------
# Load data
# ---------------------------------------------------------------------------
df = load_data(DATA_SOURCE)

if df.empty:
    st.warning("No triage data available. Select a data source from the sidebar.")
    st.stop()

# ---------------------------------------------------------------------------
# Header metrics
# ---------------------------------------------------------------------------
st.title("🛡️ Wazuh LLM Triage Dashboard")
st.caption("Real-time monitoring of AI-powered security alert triage")

col1, col2, col3, col4, col5 = st.columns(5)

total_alerts = len(df)
critical_count = len(df[df["severity"] == "CRITICAL"]) if "severity" in df.columns else 0
high_count = len(df[df["severity"] == "HIGH"]) if "severity" in df.columns else 0
total_cost = df["cost_usd"].sum() if "cost_usd" in df.columns else 0
avg_latency = df["latency_ms"].mean() if "latency_ms" in df.columns else 0

col1.metric("Total Alerts", total_alerts)
col2.metric("Critical", critical_count, delta=None)
col3.metric("High", high_count, delta=None)
col4.metric("Total Cost", f"${total_cost:.4f}")
col5.metric("Avg Latency", f"{avg_latency:.0f}ms")

st.markdown("---")

# ---------------------------------------------------------------------------
# Row 1: Severity distribution + Timeline
# ---------------------------------------------------------------------------
row1_left, row1_right = st.columns(2)

with row1_left:
    st.subheader("Severity Distribution")
    if "severity" in df.columns:
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        severity_colors = {
            "CRITICAL": "#dc3545",
            "HIGH": "#fd7e14",
            "MEDIUM": "#ffc107",
            "LOW": "#28a745",
        }
        sev_counts = df["severity"].value_counts().reindex(severity_order, fill_value=0)
        fig_sev = px.bar(
            x=sev_counts.index,
            y=sev_counts.values,
            color=sev_counts.index,
            color_discrete_map=severity_colors,
            labels={"x": "Severity", "y": "Count"},
        )
        fig_sev.update_layout(showlegend=False, height=350)
        st.plotly_chart(fig_sev, use_container_width=True)

with row1_right:
    st.subheader("Alert Timeline")
    if "timestamp" in df.columns and "severity" in df.columns:
        fig_timeline = px.scatter(
            df,
            x="timestamp",
            y="severity",
            color="severity",
            color_discrete_map=severity_colors,
            hover_data=["rule_description", "agent_name", "confidence"],
            labels={"timestamp": "Time", "severity": "Severity"},
        )
        fig_timeline.update_layout(height=350)
        st.plotly_chart(fig_timeline, use_container_width=True)

# ---------------------------------------------------------------------------
# Row 2: Confidence + Cost/Latency
# ---------------------------------------------------------------------------
row2_left, row2_right = st.columns(2)

with row2_left:
    st.subheader("Confidence Distribution")
    if "confidence" in df.columns:
        fig_conf = px.histogram(
            df,
            x="confidence",
            nbins=20,
            color="severity" if "severity" in df.columns else None,
            color_discrete_map=severity_colors if "severity" in df.columns else None,
            labels={"confidence": "Model Confidence", "count": "Alerts"},
        )
        fig_conf.update_layout(height=350, bargap=0.05)
        st.plotly_chart(fig_conf, use_container_width=True)

with row2_right:
    st.subheader("Cost & Latency per Alert")
    if "cost_usd" in df.columns and "latency_ms" in df.columns:
        fig_cost = px.scatter(
            df,
            x="latency_ms",
            y="cost_usd",
            color="severity" if "severity" in df.columns else None,
            color_discrete_map=severity_colors if "severity" in df.columns else None,
            size="confidence" if "confidence" in df.columns else None,
            hover_data=["rule_description"],
            labels={"latency_ms": "Latency (ms)", "cost_usd": "Cost (USD)"},
        )
        fig_cost.update_layout(height=350)
        st.plotly_chart(fig_cost, use_container_width=True)

st.markdown("---")

# ---------------------------------------------------------------------------
# Row 3: False Positive breakdown + MITRE techniques
# ---------------------------------------------------------------------------
row3_left, row3_right = st.columns(2)

with row3_left:
    st.subheader("False Positive Likelihood")
    if "false_positive_likelihood" in df.columns:
        fp_colors = {"LOW": "#28a745", "MEDIUM": "#ffc107", "HIGH": "#dc3545"}
        fp_counts = df["false_positive_likelihood"].value_counts()
        fig_fp = px.pie(
            names=fp_counts.index,
            values=fp_counts.values,
            color=fp_counts.index,
            color_discrete_map=fp_colors,
        )
        fig_fp.update_layout(height=350)
        st.plotly_chart(fig_fp, use_container_width=True)

with row3_right:
    st.subheader("MITRE ATT&CK Techniques")
    if "mitre_techniques" in df.columns:
        # Flatten technique strings (may be comma-separated)
        all_techniques = []
        for tech in df["mitre_techniques"].dropna():
            if isinstance(tech, str):
                all_techniques.extend([t.strip() for t in tech.split(",")])
            elif isinstance(tech, list):
                all_techniques.extend([str(t) for t in tech])

        if all_techniques:
            tech_counts = pd.Series(all_techniques).value_counts().head(10)
            fig_mitre = px.bar(
                x=tech_counts.values,
                y=tech_counts.index,
                orientation="h",
                labels={"x": "Count", "y": "Technique"},
                color_discrete_sequence=["#0d6efd"],
            )
            fig_mitre.update_layout(height=350, yaxis={"categoryorder": "total ascending"})
            st.plotly_chart(fig_mitre, use_container_width=True)
        else:
            st.info("No MITRE techniques identified yet.")

st.markdown("---")

# ---------------------------------------------------------------------------
# Alert Details Table
# ---------------------------------------------------------------------------
st.subheader("Alert Details")

display_cols = [
    c for c in [
        "timestamp", "severity", "rule_description", "agent_name",
        "source_ip", "confidence", "false_positive_likelihood",
        "summary", "cost_usd", "latency_ms",
    ]
    if c in df.columns
]

# Severity filter
if "severity" in df.columns:
    severity_filter = st.multiselect(
        "Filter by severity",
        options=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
    )
    filtered_df = df[df["severity"].isin(severity_filter)]
else:
    filtered_df = df

st.dataframe(
    filtered_df[display_cols].sort_values("timestamp", ascending=False)
    if "timestamp" in filtered_df.columns
    else filtered_df[display_cols],
    use_container_width=True,
    height=400,
)

# ---------------------------------------------------------------------------
# Expandable: Raw alert detail
# ---------------------------------------------------------------------------
st.markdown("---")
st.subheader("Alert Inspector")
if "rule_description" in df.columns:
    selected_alert = st.selectbox(
        "Select an alert to inspect",
        options=filtered_df.index,
        format_func=lambda i: f"{filtered_df.loc[i, 'timestamp']} — {filtered_df.loc[i, 'rule_description']}"
        if "timestamp" in filtered_df.columns
        else f"Alert {i}",
    )
    if selected_alert is not None:
        alert_data = filtered_df.loc[selected_alert]
        col_a, col_b = st.columns(2)
        with col_a:
            st.markdown("**Triage Summary**")
            st.write(alert_data.get("summary", "N/A"))
            st.markdown("**Recommended Actions**")
            st.write(alert_data.get("recommended_actions", "N/A"))
        with col_b:
            st.markdown("**Details**")
            st.json({
                "severity": alert_data.get("severity"),
                "confidence": alert_data.get("confidence"),
                "false_positive": alert_data.get("false_positive_likelihood"),
                "mitre": alert_data.get("mitre_techniques"),
                "agent": alert_data.get("agent_name"),
                "source_ip": alert_data.get("source_ip"),
                "tokens": f"{alert_data.get('input_tokens', 0)}+{alert_data.get('output_tokens', 0)}",
                "cost": f"${alert_data.get('cost_usd', 0):.4f}",
                "latency": f"{alert_data.get('latency_ms', 0)}ms",
            })

# ---------------------------------------------------------------------------
# Auto-refresh
# ---------------------------------------------------------------------------
if AUTO_REFRESH:
    time.sleep(30)
    st.rerun()
