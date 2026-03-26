"""
Experiment Tracking for LLM Triage Prompt Engineering

Systematically compares different prompt configurations, models,
and parameters against the labeled evaluation dataset. Tracks every
experiment with full reproducibility metadata.

This script demonstrates the ML engineering workflow:
  1. Define a hypothesis (e.g., "few-shot examples improve severity accuracy")
  2. Run the eval pipeline with the experimental config
  3. Record results with full provenance
  4. Compare against baseline

Usage:
    python experiment_tracking.py                     # Run baseline
    python experiment_tracking.py --experiment few-shot
    python experiment_tracking.py --compare           # Compare all runs

Results are saved to experiments/ as timestamped JSON files.
"""

import json
import os
import sys
import argparse
import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path

# Add llm-triage to path
sys.path.insert(0, str(Path(__file__).parent.parent / "llm-triage"))

from eval.evaluate import run_evaluation, load_system_prompt

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("experiments")

EXPERIMENTS_DIR = Path(__file__).parent / "experiments"
PROMPTS_DIR = Path(__file__).parent.parent / "llm-triage" / "prompts"


# ---------------------------------------------------------------------------
# Prompt variants for experimentation
# ---------------------------------------------------------------------------

PROMPT_VARIANTS = {
    "baseline": {
        "description": "Default system prompt — zero-shot, no examples",
        "prompt_file": "triage_system.txt",
        "modifications": None,
    },
    "few-shot": {
        "description": "Add 2 worked examples to the system prompt",
        "prompt_file": "triage_system.txt",
        "modifications": {
            "append": """

EXAMPLES — here are two worked examples to calibrate your assessments:

Example 1 (benign):
Alert: Registry Key 'HKLM\\System\\CurrentControlSet\\Services\\W32Time\\SecureTimeLimits' modified
Expected: SEVERITY: LOW, FALSE POSITIVE: HIGH — routine NTP sync updates this key automatically.

Example 2 (malicious):
Alert: PowerShell encoded command detected: powershell.exe -enc [base64 IEX download cradle]
Expected: SEVERITY: CRITICAL, FALSE POSITIVE: LOW — base64-encoded IEX download cradle is a classic post-exploitation technique.
""",
        },
    },
    "strict-format": {
        "description": "More aggressive format instructions, shorter word limit",
        "prompt_file": "triage_system.txt",
        "modifications": {
            "replace": {
                "Keep total response under 300 words": "Keep total response under 150 words. Be extremely concise.",
            },
        },
    },
    "threat-hunter": {
        "description": "Adopt threat hunter persona instead of SOC analyst",
        "prompt_file": "triage_system.txt",
        "modifications": {
            "replace": {
                "You are a senior SOC analyst performing automated triage of Wazuh SIEM alerts.": (
                    "You are a senior threat hunter analyzing Wazuh SIEM alerts. "
                    "You assume breach and look for evidence of attacker activity. "
                    "You are naturally suspicious and err on the side of caution."
                ),
            },
        },
    },
}


def build_prompt(variant_name: str) -> str:
    """Build the system prompt for a given experiment variant."""
    variant = PROMPT_VARIANTS[variant_name]
    base_prompt = (PROMPTS_DIR / variant["prompt_file"]).read_text()

    mods = variant.get("modifications")
    if not mods:
        return base_prompt

    prompt = base_prompt

    if "replace" in mods:
        for old, new in mods["replace"].items():
            prompt = prompt.replace(old, new)

    if "append" in mods:
        prompt += mods["append"]

    if "prepend" in mods:
        prompt = mods["prepend"] + prompt

    return prompt


def run_experiment(
    variant_name: str,
    model: str = "claude-sonnet-4-6",
    dataset_path: str = None,
    verbose: bool = False,
) -> dict:
    """
    Run a single experiment and save results.

    Returns the experiment record dict.
    """
    EXPERIMENTS_DIR.mkdir(parents=True, exist_ok=True)

    variant = PROMPT_VARIANTS.get(variant_name)
    if not variant:
        logger.error("Unknown variant: %s. Available: %s",
                      variant_name, list(PROMPT_VARIANTS.keys()))
        sys.exit(1)

    prompt_text = build_prompt(variant_name)
    prompt_hash = hashlib.sha256(prompt_text.encode()).hexdigest()[:12]

    logger.info("=" * 60)
    logger.info("EXPERIMENT: %s", variant_name)
    logger.info("Description: %s", variant["description"])
    logger.info("Model: %s", model)
    logger.info("Prompt hash: %s", prompt_hash)
    logger.info("=" * 60)

    # Temporarily override the system prompt file
    temp_prompt_path = PROMPTS_DIR / f"_experiment_{variant_name}.txt"
    temp_prompt_path.write_text(prompt_text)

    try:
        # Monkey-patch the prompt path for the eval run
        original_prompt = (PROMPTS_DIR / "triage_system.txt").read_text()
        (PROMPTS_DIR / "triage_system.txt").write_text(prompt_text)

        results = run_evaluation(
            model=model,
            dataset_path=dataset_path,
            verbose=verbose,
        )

        # Restore original prompt
        (PROMPTS_DIR / "triage_system.txt").write_text(original_prompt)

    finally:
        # Clean up temp file
        if temp_prompt_path.exists():
            temp_prompt_path.unlink()

    # Build experiment record
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    experiment_record = {
        "experiment_id": f"{variant_name}_{model}_{timestamp}",
        "variant": variant_name,
        "description": variant["description"],
        "model": model,
        "prompt_hash": prompt_hash,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "aggregate": results.get("aggregate", {}),
        "per_alert_results": results.get("results", []),
    }

    # Save to file
    output_file = EXPERIMENTS_DIR / f"{experiment_record['experiment_id']}.json"
    with open(output_file, "w") as f:
        json.dump(experiment_record, f, indent=2)
    logger.info("Results saved to %s", output_file)

    return experiment_record


def compare_experiments():
    """Load all experiment results and print a comparison table."""
    EXPERIMENTS_DIR.mkdir(parents=True, exist_ok=True)

    results = []
    for f in sorted(EXPERIMENTS_DIR.glob("*.json")):
        with open(f) as fh:
            results.append(json.load(fh))

    if not results:
        print("No experiments found. Run some first!")
        return

    # Print comparison table
    print(f"\n{'='*90}")
    print("EXPERIMENT COMPARISON")
    print(f"{'='*90}")
    print(f"{'Variant':<18} {'Model':<22} {'Sev Acc':<9} {'Sev ±1':<9} "
          f"{'FP Acc':<9} {'MITRE F1':<9} {'Benign':<9} {'Cost':<8}")
    print(f"{'-'*90}")

    for r in results:
        agg = r.get("aggregate", {})
        sev = agg.get("severity", {})
        fp = agg.get("false_positive", {})
        mitre = agg.get("mitre", {})
        benign = agg.get("benign_detection", {})

        print(
            f"{r['variant']:<18} "
            f"{r['model']:<22} "
            f"{sev.get('exact_accuracy', 0):<9.1%} "
            f"{sev.get('within_one_accuracy', 0):<9.1%} "
            f"{fp.get('exact_accuracy', 0):<9.1%} "
            f"{mitre.get('avg_f1', 0):<9.1%} "
            f"{benign.get('accuracy', 0):<9.1%} "
            f"${agg.get('total_cost_usd', 0):<7.4f}"
        )

    print(f"{'='*90}")
    print(f"Total experiments: {len(results)}")


def main():
    parser = argparse.ArgumentParser(description="LLM Triage Experiment Tracker")
    parser.add_argument(
        "--experiment",
        default="baseline",
        choices=list(PROMPT_VARIANTS.keys()),
        help="Which prompt variant to test",
    )
    parser.add_argument(
        "--model",
        default=os.environ.get("CLAUDE_MODEL", "claude-sonnet-4-6"),
        help="Claude model to use",
    )
    parser.add_argument(
        "--dataset",
        default=None,
        help="Path to labeled dataset JSON",
    )
    parser.add_argument(
        "--compare",
        action="store_true",
        help="Compare all experiment results",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show per-alert details",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all prompt variants",
    )
    args = parser.parse_args()

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if args.compare:
        compare_experiments()
        return

    if args.all:
        for variant in PROMPT_VARIANTS:
            run_experiment(
                variant_name=variant,
                model=args.model,
                dataset_path=args.dataset,
                verbose=args.verbose,
            )
        compare_experiments()
    else:
        run_experiment(
            variant_name=args.experiment,
            model=args.model,
            dataset_path=args.dataset,
            verbose=args.verbose,
        )


if __name__ == "__main__":
    main()
