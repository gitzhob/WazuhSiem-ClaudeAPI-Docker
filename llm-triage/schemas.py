"""
Structured output schemas for LLM triage and hunt responses.

Uses Pydantic models that LangChain's `with_structured_output()` converts
into Anthropic tool_use schemas automatically. This gives us:
  - Python-native type validation (not raw JSON dicts)
  - Automatic schema generation for any LLM provider
  - IDE autocomplete and type checking
  - Easy serialization to/from dicts for OpenSearch storage

The Pydantic models replace the hand-written TRIAGE_TOOL and HUNT_TOOL
JSON schemas from the direct Anthropic SDK version.
"""

from typing import Literal, Optional
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Triage schemas
# ---------------------------------------------------------------------------


class LikelyCause(BaseModel):
    """One possible explanation for why this alert fired."""

    explanation: str = Field(description="What likely caused this alert.")
    benign: bool = Field(
        description="True if this cause is benign/expected, False if malicious."
    )


class MitreAttack(BaseModel):
    """A single MITRE ATT&CK technique reference."""

    technique_id: str = Field(
        description="MITRE ATT&CK technique ID (e.g., T1110, T1565.001)."
    )
    technique_name: str = Field(description="Human-readable technique name.")


class TriageResult(BaseModel):
    """
    Structured triage assessment for a Wazuh security alert.

    LangChain passes this model to `with_structured_output()`, which
    tells Claude to return data matching this exact shape. Equivalent
    to the old TRIAGE_TOOL JSON schema but with Python type safety.
    """

    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = Field(
        description="Overall threat severity based on actual risk, not just the Wazuh rule level."
    )
    summary: str = Field(
        description="1-2 sentence plain-English summary. No jargon a junior admin wouldn't know."
    )
    likely_cause: list[LikelyCause] = Field(
        min_length=1,
        max_length=3,
        description="Possible causes ranked by likelihood (most likely first).",
    )
    actions: list[str] = Field(
        min_length=1,
        max_length=5,
        description="Recommended actions, most urgent first. Include specific commands or file paths.",
    )
    mitre_attack: list[MitreAttack] = Field(
        default_factory=list,
        description="Relevant MITRE ATT&CK techniques. Empty list if N/A.",
    )
    false_positive_likelihood: Literal["HIGH", "MEDIUM", "LOW"] = Field(
        description="How likely this alert is a false positive."
    )
    false_positive_reasoning: str = Field(
        description="One-line explanation of the false positive assessment."
    )
    related_alerts: str = Field(
        description="Other Wazuh rules, Windows Event IDs, or alert patterns to correlate with. 'None' if standalone."
    )
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Model's self-assessed confidence in this triage (0.0-1.0). Lower if alert context is ambiguous.",
    )


# ---------------------------------------------------------------------------
# Hunt schemas
# ---------------------------------------------------------------------------


class HuntFinding(BaseModel):
    """A single suspicious pattern found during a threat hunt."""

    title: str = Field(description="Short title for this finding.")
    description: str = Field(
        description="Detailed explanation of the suspicious pattern."
    )
    evidence: list[str] = Field(
        default_factory=list,
        description="Specific log entries or event details supporting this finding.",
    )
    mitre_technique: Optional[str] = Field(
        default=None,
        description="MITRE ATT&CK technique ID (e.g., T1059.001).",
    )
    recommended_action: str = Field(
        description="What to do about this finding."
    )


class RecommendedRule(BaseModel):
    """A suggested Wazuh detection rule based on hunt findings."""

    description: str = Field(description="What this rule would detect.")
    wazuh_rule_xml: Optional[str] = Field(
        default=None,
        description="Suggested Wazuh XML rule definition.",
    )


class HuntResult(BaseModel):
    """
    Structured findings from a proactive threat hunt.

    Replaces the old HUNT_TOOL JSON schema. LangChain converts this
    Pydantic model into the appropriate tool_use schema for Claude.
    """

    threat_detected: bool = Field(
        description="True if evidence of suspicious/malicious activity was found."
    )
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"] = Field(
        description="Overall severity of findings."
    )
    summary: str = Field(
        description="2-3 sentence summary of what you found (or didn't find)."
    )
    findings: list[HuntFinding] = Field(
        default_factory=list,
        description="Individual findings. Empty list if nothing suspicious.",
    )
    patterns_checked: list[str] = Field(
        default_factory=list,
        description="What attack patterns you looked for (even if not found).",
    )
    recommended_rules: list[RecommendedRule] = Field(
        default_factory=list,
        description="Suggested new Wazuh detection rules based on findings.",
    )
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Confidence in overall assessment (0.0-1.0).",
    )


# ---------------------------------------------------------------------------
# Conversion utilities
# ---------------------------------------------------------------------------


def triage_to_flat_text(triage) -> str:
    """
    Convert a TriageResult (Pydantic model or dict) to human-readable text.
    Accepts both a TriageResult instance and a plain dict for backward
    compatibility with OpenSearch documents and test fixtures.
    """
    # Support both Pydantic model and dict
    if isinstance(triage, BaseModel):
        t = triage.model_dump()
    else:
        t = triage

    lines = []
    lines.append(f"SEVERITY: {t['severity']}")
    lines.append(f"CONFIDENCE: {t.get('confidence', 'N/A')}")
    lines.append(f"\nSUMMARY: {t['summary']}")

    lines.append("\nLIKELY CAUSE:")
    for i, cause in enumerate(t.get("likely_cause", []), 1):
        tag = "benign" if cause.get("benign") else "malicious"
        lines.append(f"  {i}. [{tag}] {cause['explanation']}")

    lines.append("\nACTIONS:")
    for i, action in enumerate(t.get("actions", []), 1):
        lines.append(f"  {i}. {action}")

    mitre = t.get("mitre_attack", [])
    if mitre:
        techniques = ", ".join(
            f"{m['technique_id']} \u2013 {m['technique_name']}" for m in mitre
        )
        lines.append(f"\nMITRE ATT&CK: {techniques}")
    else:
        lines.append("\nMITRE ATT&CK: N/A")

    fp = t.get("false_positive_likelihood", "N/A")
    fp_reason = t.get("false_positive_reasoning", "")
    lines.append(f"\nFALSE POSITIVE LIKELIHOOD: {fp} \u2014 {fp_reason}")

    lines.append(f"\nRELATED ALERTS: {t.get('related_alerts', 'None')}")

    return "\n".join(lines)


def hunt_to_flat_text(hunt) -> str:
    """
    Convert a HuntResult (Pydantic model or dict) to human-readable text.
    """
    if isinstance(hunt, BaseModel):
        h = hunt.model_dump()
    else:
        h = hunt

    lines = []
    lines.append(f"THREAT DETECTED: {h.get('threat_detected', False)}")
    lines.append(f"SEVERITY: {h.get('severity', 'N/A')}")
    lines.append(f"CONFIDENCE: {h.get('confidence', 'N/A')}")
    lines.append(f"\nSUMMARY: {h.get('summary', '')}")

    for i, f in enumerate(h.get("findings", []), 1):
        lines.append(f"\n--- Finding {i}: {f['title']} ---")
        lines.append(f"  {f['description']}")
        if f.get("mitre_technique"):
            lines.append(f"  MITRE: {f['mitre_technique']}")
        lines.append(f"  Action: {f['recommended_action']}")
        if f.get("evidence"):
            for ev in f["evidence"][:3]:
                lines.append(f"  Evidence: {ev[:120]}")

    if h.get("recommended_rules"):
        lines.append("\n--- Suggested Detection Rules ---")
        for rule in h["recommended_rules"]:
            lines.append(f"  {rule['description']}")
            if rule.get("wazuh_rule_xml"):
                lines.append(f"  {rule['wazuh_rule_xml'][:200]}")

    if h.get("patterns_checked"):
        lines.append(f"\nPATTERNS CHECKED: {', '.join(h['patterns_checked'])}")

    return "\n".join(lines)
