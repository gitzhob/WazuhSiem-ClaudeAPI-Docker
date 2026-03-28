"""
Evaluation framework for the LLM triage pipeline.

Runs Claude triage against a labeled dataset of alerts with known
ground-truth severity, false positive likelihood, and MITRE mappings.
Computes accuracy, agreement rates, and per-class metrics.

Now powered by LangChain — uses ChatAnthropic + with_structured_output()
with the TriageResult Pydantic model instead of raw tool_use parsing.

Usage:
    python -m eval.evaluate                    # Run full eval
    python -m eval.evaluate --model claude-sonnet-4-6  # Specific model
    python -m eval.evaluate --verbose          # Show per-alert details
    python -m eval.evaluate --output results.json      # Save results

This is the core ML engineering deliverable — it measures whether
the model's triage assessments are actually correct, and provides
the numbers needed to compare prompts, models, and configurations.
"""

import json
import sys
import os
import argparse
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

# Add parent dir to path so we can import from llm-triage
sys.path.insert(0, str(Path(__file__).parent.parent))

from langchain_anthropic import ChatAnthropic
from langchain_core.prompts import ChatPromptTemplate

from schemas import TriageResult, triage_to_flat_text
from metrics import MetricsTracker
from callbacks import MetricsCallbackHandler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("eval")

# Severity ordering for "within-1" scoring
SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
FP_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}


def load_dataset(path: Optional[str] = None) -> list:
    """Load the labeled evaluation dataset."""
    if path is None:
        path = Path(__file__).parent / "labeled_dataset.json"
    with open(path) as f:
        return json.load(f)


def load_system_prompt() -> str:
    """Load the triage system prompt."""
    prompt_path = Path(__file__).parent.parent / "prompts" / "triage_system.txt"
    return prompt_path.read_text()


# LangChain prompt template for evaluation
EVAL_PROMPT = ChatPromptTemplate.from_messages([
    ("system", "{system_prompt}"),
    ("human", (
        "Analyze the following Wazuh security alert and provide your "
        "triage assessment.\n\n"
        "```json\n{alert_text}\n```"
    )),
])


def triage_alert_structured(
    chain,
    alert: dict,
    system_prompt: str,
    callback_handler: MetricsCallbackHandler = None,
) -> Optional[dict]:
    """
    Send an alert through the LangChain chain for structured output.

    Returns:
        triage_result_dict or None if the chain fails
    """
    alert_text = json.dumps(alert, indent=2, default=str)

    invoke_kwargs = {
        "system_prompt": system_prompt,
        "alert_text": alert_text,
    }

    config = {}
    if callback_handler:
        callback_handler.reset_last()
        config["callbacks"] = [callback_handler]

    result: TriageResult = chain.invoke(invoke_kwargs, config=config)

    # Convert Pydantic model to dict
    return result.model_dump()


def score_severity(predicted: str, actual: str) -> dict:
    """Score severity prediction against ground truth."""
    exact_match = predicted == actual
    pred_val = SEVERITY_ORDER.get(predicted, -1)
    actual_val = SEVERITY_ORDER.get(actual, -1)
    distance = abs(pred_val - actual_val)
    within_one = distance <= 1

    return {
        "exact_match": exact_match,
        "within_one": within_one,
        "distance": distance,
        "predicted": predicted,
        "actual": actual,
    }


def score_false_positive(predicted: str, actual: str) -> dict:
    """Score false positive likelihood prediction."""
    exact_match = predicted == actual
    pred_val = FP_ORDER.get(predicted, -1)
    actual_val = FP_ORDER.get(actual, -1)
    distance = abs(pred_val - actual_val)
    within_one = distance <= 1

    return {
        "exact_match": exact_match,
        "within_one": within_one,
        "distance": distance,
        "predicted": predicted,
        "actual": actual,
    }


def score_mitre(predicted_techniques: list, actual_techniques: list) -> dict:
    """Score MITRE ATT&CK technique identification."""
    pred_ids = set(t.get("technique_id", "") for t in predicted_techniques)
    actual_ids = set(actual_techniques)

    if not actual_ids and not pred_ids:
        return {"precision": 1.0, "recall": 1.0, "f1": 1.0, "predicted": [], "actual": []}

    true_positives = pred_ids & actual_ids
    precision = len(true_positives) / max(len(pred_ids), 1)
    recall = len(true_positives) / max(len(actual_ids), 1)
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )

    return {
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "predicted": sorted(pred_ids),
        "actual": sorted(actual_ids),
    }


def score_benign_detection(triage: dict, ground_truth: dict) -> dict:
    """Score whether the model correctly identified benign vs malicious."""
    # Check if the most-likely cause is marked benign
    causes = triage.get("likely_cause", [])
    predicted_benign = causes[0].get("benign", False) if causes else False
    actual_benign = ground_truth.get("is_benign", False)

    return {
        "correct": predicted_benign == actual_benign,
        "predicted_benign": predicted_benign,
        "actual_benign": actual_benign,
    }


def run_evaluation(
    model: str = "claude-sonnet-4-6",
    dataset_path: Optional[str] = None,
    verbose: bool = False,
) -> dict:
    """
    Run the full evaluation pipeline.

    Uses LangChain's ChatAnthropic + with_structured_output(TriageResult)
    to get validated Pydantic model responses from Claude.

    Returns a results dict with per-alert scores and aggregate metrics.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        logger.error("ANTHROPIC_API_KEY not set")
        sys.exit(1)

    # Build the LangChain chain
    llm = ChatAnthropic(
        model=model,
        api_key=api_key,
        max_tokens=1500,
    )
    structured_llm = llm.with_structured_output(TriageResult)
    chain = EVAL_PROMPT | structured_llm

    system_prompt = load_system_prompt()
    dataset = load_dataset(dataset_path)
    tracker = MetricsTracker()
    callback_handler = MetricsCallbackHandler(model=model)

    logger.info("=" * 60)
    logger.info("EVALUATION RUN")
    logger.info("  Model: %s", model)
    logger.info("  Dataset: %d alerts", len(dataset))
    logger.info("  Framework: LangChain + with_structured_output + callbacks")
    logger.info("=" * 60)

    results = []
    for i, entry in enumerate(dataset):
        alert = entry["alert"]
        ground_truth = entry["ground_truth"]

        logger.info(
            "[%d/%d] Evaluating: %s",
            i + 1,
            len(dataset),
            entry["description"],
        )

        timer = tracker.start_timer()
        try:
            triage = triage_alert_structured(
                chain, alert, system_prompt, callback_handler
            )

            # Get real metrics from the callback handler
            latency_ms = callback_handler.last_latency_ms
            cost_usd = callback_handler.last_cost_usd
            tokens = callback_handler.last_input_tokens + callback_handler.last_output_tokens

        except Exception as e:
            logger.error("Failed on %s: %s", entry["id"], e)
            results.append({
                "id": entry["id"],
                "description": entry["description"],
                "error": str(e),
            })
            continue

        if not triage:
            logger.error("No structured output returned for %s", entry["id"])
            results.append({
                "id": entry["id"],
                "description": entry["description"],
                "error": "No structured output from model",
            })
            continue

        # Score each dimension
        severity_score = score_severity(
            triage.get("severity", ""), ground_truth["severity"]
        )
        fp_score = score_false_positive(
            triage.get("false_positive_likelihood", ""),
            ground_truth["false_positive_likelihood"],
        )
        mitre_score = score_mitre(
            triage.get("mitre_attack", []),
            ground_truth.get("mitre_techniques", []),
        )
        benign_score = score_benign_detection(triage, ground_truth)

        result = {
            "id": entry["id"],
            "description": entry["description"],
            "scores": {
                "severity": severity_score,
                "false_positive": fp_score,
                "mitre": mitre_score,
                "benign_detection": benign_score,
            },
            "model_confidence": triage.get("confidence", 0),
            "cost_usd": cost_usd,
            "latency_ms": latency_ms,
            "tokens": tokens,
        }

        if verbose:
            result["triage_output"] = triage
            result["ground_truth"] = ground_truth

        results.append(result)

        if verbose:
            print(f"\n{'─'*60}")
            print(f"Alert: {entry['description']}")
            print(f"Severity: {severity_score['predicted']} vs {severity_score['actual']} "
                  f"({'✓' if severity_score['exact_match'] else '✗'})")
            print(f"FP: {fp_score['predicted']} vs {fp_score['actual']} "
                  f"({'✓' if fp_score['exact_match'] else '✗'})")
            print(f"MITRE F1: {mitre_score['f1']}")
            print(f"Benign: {'✓' if benign_score['correct'] else '✗'}")
            print(f"Confidence: {triage.get('confidence', 'N/A')}")
            print(f"{'─'*60}")

    # Compute aggregate scores
    valid_results = [r for r in results if "error" not in r]
    n = len(valid_results)

    if n == 0:
        logger.error("No successful evaluations")
        return {"results": results, "aggregate": {}, "errors": len(results)}

    aggregate = {
        "model": model,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "framework": "langchain",
        "dataset_size": len(dataset),
        "successful_evals": n,
        "errors": len(dataset) - n,
        "severity": {
            "exact_accuracy": round(
                sum(1 for r in valid_results if r["scores"]["severity"]["exact_match"]) / n, 3
            ),
            "within_one_accuracy": round(
                sum(1 for r in valid_results if r["scores"]["severity"]["within_one"]) / n, 3
            ),
            "avg_distance": round(
                sum(r["scores"]["severity"]["distance"] for r in valid_results) / n, 3
            ),
        },
        "false_positive": {
            "exact_accuracy": round(
                sum(1 for r in valid_results if r["scores"]["false_positive"]["exact_match"]) / n, 3
            ),
            "within_one_accuracy": round(
                sum(1 for r in valid_results if r["scores"]["false_positive"]["within_one"]) / n, 3
            ),
        },
        "mitre": {
            "avg_precision": round(
                sum(r["scores"]["mitre"]["precision"] for r in valid_results) / n, 3
            ),
            "avg_recall": round(
                sum(r["scores"]["mitre"]["recall"] for r in valid_results) / n, 3
            ),
            "avg_f1": round(
                sum(r["scores"]["mitre"]["f1"] for r in valid_results) / n, 3
            ),
        },
        "benign_detection": {
            "accuracy": round(
                sum(1 for r in valid_results if r["scores"]["benign_detection"]["correct"]) / n, 3
            ),
        },
        "avg_confidence": round(
            sum(r["model_confidence"] for r in valid_results) / n, 3
        ),
        "total_cost_usd": round(
            sum(r["cost_usd"] for r in valid_results), 4
        ),
        "avg_latency_ms": round(
            sum(r["latency_ms"] for r in valid_results) / n, 1
        ),
    }

    # Print summary
    print(f"\n{'='*60}")
    print("EVALUATION RESULTS")
    print(f"{'='*60}")
    print(f"Model:              {model}")
    print(f"Framework:          LangChain")
    print(f"Alerts evaluated:   {n}/{len(dataset)}")
    print(f"")
    print(f"Severity accuracy:  {aggregate['severity']['exact_accuracy']:.1%} exact, "
          f"{aggregate['severity']['within_one_accuracy']:.1%} within-1")
    print(f"FP accuracy:        {aggregate['false_positive']['exact_accuracy']:.1%} exact")
    print(f"MITRE F1:           {aggregate['mitre']['avg_f1']:.1%}")
    print(f"Benign detection:   {aggregate['benign_detection']['accuracy']:.1%}")
    print(f"Avg confidence:     {aggregate['avg_confidence']:.3f}")
    print(f"")
    print(f"Total cost:         ${aggregate['total_cost_usd']:.4f}")
    print(f"Avg latency:        {aggregate['avg_latency_ms']:.0f}ms")
    print(f"{'='*60}")

    return {"results": results, "aggregate": aggregate}


def main():
    parser = argparse.ArgumentParser(description="Evaluate LLM triage pipeline")
    parser.add_argument(
        "--model",
        default=os.environ.get("CLAUDE_MODEL", "claude-sonnet-4-6"),
        help="Claude model to evaluate",
    )
    parser.add_argument(
        "--dataset",
        default=None,
        help="Path to labeled dataset JSON",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Path to save results JSON",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show per-alert details",
    )
    args = parser.parse_args()

    # Suppress SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    results = run_evaluat