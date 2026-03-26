"""
Structured output schemas for LLM triage responses.

Defines the Anthropic tool-use schema that forces Claude to return
typed JSON instead of free text. This enables:
  - Programmatic evaluation and scoring
  - Consistent OpenSearch indexing
  - Metric computation (accuracy, precision, recall)
  - Feedback loop integration
"""

# ---------------------------------------------------------------------------
# The tool definition passed to Claude's tool_use feature.
# Claude "calls" this tool with structured arguments, which we capture
# as the triage result. This guarantees a consistent JSON shape every time.
# ---------------------------------------------------------------------------

TRIAGE_TOOL = {
    "name": "submit_triage",
    "description": (
        "Submit your structured triage assessment for a Wazuh security alert. "
        "You MUST call this tool with your analysis — do not respond with plain text."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "severity": {
                "type": "string",
                "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                "description": "Overall threat severity based on actual risk, not just the Wazuh rule level.",
            },
            "summary": {
                "type": "string",
                "description": (
                    "1-2 sentence plain-English summary. "
                    "No jargon a junior admin wouldn't know."
                ),
            },
            "likely_cause": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "explanation": {
                            "type": "string",
                            "description": "What likely caused this alert.",
                        },
                        "benign": {
                            "type": "boolean",
                            "description": "True if this cause is benign/expected, False if malicious.",
                        },
                    },
                    "required": ["explanation", "benign"],
                },
                "minItems": 1,
                "maxItems": 3,
                "description": "Possible causes ranked by likelihood (most likely first).",
            },
            "actions": {
                "type": "array",
                "items": {"type": "string"},
                "minItems": 1,
                "maxItems": 5,
                "description": (
                    "Recommended actions, most urgent first. "
                    "Include specific commands, queries, or file paths."
                ),
            },
            "mitre_attack": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "technique_id": {
                            "type": "string",
                            "description": "MITRE ATT&CK technique ID (e.g., T1110, T1565.001).",
                        },
                        "technique_name": {
                            "type": "string",
                            "description": "Human-readable technique name.",
                        },
                    },
                    "required": ["technique_id", "technique_name"],
                },
                "description": "Relevant MITRE ATT&CK techniques. Empty array if N/A.",
            },
            "false_positive_likelihood": {
                "type": "string",
                "enum": ["HIGH", "MEDIUM", "LOW"],
                "description": "How likely this alert is a false positive.",
            },
            "false_positive_reasoning": {
                "type": "string",
                "description": "One-line explanation of the false positive assessment.",
            },
            "related_alerts": {
                "type": "string",
                "description": (
                    "Other Wazuh rules, Windows Event IDs, or alert patterns "
                    "to correlate with. 'None' if standalone."
                ),
            },
            "confidence": {
                "type": "number",
                "minimum": 0.0,
                "maximum": 1.0,
                "description": (
                    "Model's self-assessed confidence in this triage (0.0-1.0). "
                    "Lower if alert context is ambiguous or incomplete."
                ),
            },
        },
        "required": [
            "severity",
            "summary",
            "likely_cause",
            "actions",
            "mitre_attack",
            "false_positive_likelihood",
            "false_positive_reasoning",
            "related_alerts",
            "confidence",
        ],
    },
}


def triage_to_flat_text(triage: dict) -> str:
    """
    Convert a structured triage dict back to human-readable text.
    Useful for console output and backward compatibility.
    """
    lines = []
    lines.append(f"SEVERITY: {triage['severity']}")
    lines.append(f"CONFIDENCE: {triage.get('confidence', 'N/A')}")
    lines.append(f"\nSUMMARY: {triage['summary']}")

    lines.append("\nLIKELY CAUSE:")
    for i, cause in enumerate(triage.get("likely_cause", []), 1):
        tag = "benign" if cause.get("benign") else "malicious"
        lines.append(f"  {i}. [{tag}] {cause['explanation']}")

    lines.append("\nACTIONS:")
    for i, action in enumerate(triage.get("actions", []), 1):
        lines.append(f"  {i}. {action}")

    mitre = triage.get("mitre_attack", [])
    if mitre:
        techniques = ", ".join(
            f"{t['technique_id']} – {t['technique_name']}" for t in mitre
        )
        lines.append(f"\nMITRE ATT&CK: {techniques}")
    else:
        lines.append("\nMITRE ATT&CK: N/A")

    fp = triage.get("false_positive_likelihood", "N/A")
    fp_reason = triage.get("false_positive_reasoning", "")
    lines.append(f"\nFALSE POSITIVE LIKELIHOOD: {fp} — {fp_reason}")

    lines.append(f"\nRELATED ALERTS: {triage.get('related_alerts', 'None')}")

    return "\n".join(lines)
