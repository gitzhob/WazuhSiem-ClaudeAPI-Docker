"""
Analyst feedback loop for LLM triage results.

Provides a mechanism for human analysts to review and correct
Claude's triage assessments. Feedback is stored in OpenSearch
and can be exported to improve the evaluation dataset.

This implements the human-in-the-loop pattern central to
production ML systems:
  1. Model makes a prediction (triage)
  2. Human reviews and optionally corrects
  3. Corrections become training/evaluation data
  4. Model performance is measured against human labels

Feedback is stored in the 'wazuh-llm-feedback' OpenSearch index.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Optional

import requests
from requests.auth import HTTPBasicAuth

logger = logging.getLogger("llm-triage.feedback")


class FeedbackStore:
    """Read/write analyst feedback to OpenSearch."""

    INDEX_NAME = "wazuh-llm-feedback"

    def __init__(self, indexer_url: str, username: str, password: str):
        self.indexer_url = indexer_url.rstrip("/")
        self.auth = HTTPBasicAuth(username, password)
        self.verify_ssl = False

    def submit_feedback(
        self,
        triage_doc_id: str,
        original_alert: dict,
        model_triage: dict,
        analyst_verdict: str,
        corrected_severity: Optional[str] = None,
        corrected_fp_likelihood: Optional[str] = None,
        corrected_is_benign: Optional[bool] = None,
        analyst_notes: str = "",
        analyst_id: str = "anonymous",
    ) -> bool:
        """
        Store analyst feedback on a triage result.

        Args:
            triage_doc_id: The OpenSearch _id of the original triage doc
            original_alert: The raw Wazuh alert
            model_triage: Claude's structured triage output
            analyst_verdict: 'agree', 'disagree', or 'partial'
            corrected_severity: If disagree, the correct severity
            corrected_fp_likelihood: If disagree, the correct FP rating
            corrected_is_benign: If disagree, whether it's actually benign
            analyst_notes: Free-text analyst commentary
            analyst_id: Who submitted the feedback
        """
        doc = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "triage_doc_id": triage_doc_id,
            "analyst_id": analyst_id,
            "analyst_verdict": analyst_verdict,
            "analyst_notes": analyst_notes,
            "model_output": {
                "severity": model_triage.get("severity"),
                "false_positive_likelihood": model_triage.get("false_positive_likelihood"),
                "confidence": model_triage.get("confidence"),
                "mitre_techniques": [
                    t.get("technique_id", "")
                    for t in model_triage.get("mitre_attack", [])
                ],
            },
            "corrections": {},
            "original_alert": {
                "rule_id": original_alert.get("rule", {}).get("id"),
                "rule_level": original_alert.get("rule", {}).get("level"),
                "rule_description": original_alert.get("rule", {}).get("description"),
            },
        }

        # Only include corrections if analyst disagrees
        if analyst_verdict in ("disagree", "partial"):
            if corrected_severity:
                doc["corrections"]["severity"] = corrected_severity
            if corrected_fp_likelihood:
                doc["corrections"]["false_positive_likelihood"] = corrected_fp_likelihood
            if corrected_is_benign is not None:
                doc["corrections"]["is_benign"] = corrected_is_benign

        try:
            response = requests.post(
                f"{self.indexer_url}/{self.INDEX_NAME}/_doc",
                auth=self.auth,
                json=doc,
                verify=self.verify_ssl,
                timeout=10,
            )
            response.raise_for_status()
            logger.info(
                "Stored feedback: verdict=%s for triage=%s",
                analyst_verdict,
                triage_doc_id,
            )
            return True
        except requests.exceptions.RequestException as e:
            logger.error("Failed to store feedback: %s", e)
            return False

    def get_feedback_stats(self) -> dict:
        """Get aggregate feedback statistics."""
        query = {
            "size": 0,
            "aggs": {
                "verdicts": {
                    "terms": {"field": "analyst_verdict.keyword"}
                },
                "severity_corrections": {
                    "filter": {"exists": {"field": "corrections.severity"}},
                    "aggs": {
                        "original": {
                            "terms": {"field": "model_output.severity.keyword"}
                        },
                        "corrected": {
                            "terms": {"field": "corrections.severity.keyword"}
                        },
                    },
                },
                "avg_model_confidence_when_correct": {
                    "filter": {"term": {"analyst_verdict.keyword": "agree"}},
                    "aggs": {
                        "avg_confidence": {
                            "avg": {"field": "model_output.confidence"}
                        }
                    },
                },
                "avg_model_confidence_when_wrong": {
                    "filter": {"term": {"analyst_verdict.keyword": "disagree"}},
                    "aggs": {
                        "avg_confidence": {
                            "avg": {"field": "model_output.confidence"}
                        }
                    },
                },
            },
        }

        try:
            response = requests.post(
                f"{self.indexer_url}/{self.INDEX_NAME}/_search",
                auth=self.auth,
                json=query,
                verify=self.verify_ssl,
                timeout=10,
            )
            response.raise_for_status()
            return response.json().get("aggregations", {})
        except requests.exceptions.RequestException as e:
            logger.error("Failed to get feedback stats: %s", e)
            return {}

    def export_as_eval_dataset(self, limit: int = 500) -> list:
        """
        Export analyst-corrected feedback as evaluation dataset entries.

        Returns data in the same format as labeled_dataset.json,
        so corrected triage results can be fed back into the eval pipeline.
        """
        query = {
            "size": limit,
            "query": {
                "bool": {
                    "must": [
                        {"terms": {"analyst_verdict.keyword": ["disagree", "partial"]}},
                        {"exists": {"field": "corrections.severity"}},
                    ]
                }
            },
            "sort": [{"timestamp": {"order": "desc"}}],
        }

        try:
            response = requests.post(
                f"{self.indexer_url}/{self.INDEX_NAME}/_search",
                auth=self.auth,
                json=query,
                verify=self.verify_ssl,
                timeout=15,
            )
            response.raise_for_status()
            hits = response.json().get("hits", {}).get("hits", [])

            dataset_entries = []
            for hit in hits:
                src = hit["_source"]
                corrections = src.get("corrections", {})
                model_out = src.get("model_output", {})

                entry = {
                    "id": f"feedback-{hit['_id'][:8]}",
                    "description": f"Analyst-corrected: {src['original_alert'].get('rule_description', 'Unknown')}",
                    "alert": src.get("original_alert", {}),
                    "ground_truth": {
                        "severity": corrections.get("severity", model_out.get("severity")),
                        "false_positive_likelihood": corrections.get(
                            "false_positive_likelihood",
                            model_out.get("false_positive_likelihood"),
                        ),
                        "mitre_techniques": model_out.get("mitre_techniques", []),
                        "is_benign": corrections.get("is_benign", True),
                        "notes": f"Analyst correction: {src.get('analyst_notes', '')}",
                    },
                }
                dataset_entries.append(entry)

            logger.info("Exported %d feedback entries as eval dataset", len(dataset_entries))
            return dataset_entries

        except requests.exceptions.RequestException as e:
            logger.error("Failed to export feedback: %s", e)
            return []
