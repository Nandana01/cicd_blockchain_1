"""
run_evaluation.py - Master script to run all evaluation experiments.

Usage:
    python run_evaluation.py --source note-app.tar --artifact-id notes-app-v1

This script orchestrates:
    1. Tamper simulation (generate tampered artifacts)
    2. Detection suite (run all detection pathways on tampered artifacts)
    3. Detection rate calculation
    4. Latency monitoring (with built-in tamper injection)
    5. Detection latency calculation
    6. Combined report generation
"""

import argparse
import json
import os
import shutil
import sys
import time
from datetime import datetime
from pathlib import Path

EVAL_DIR = Path(__file__).parent
RESULTS_DIR = EVAL_DIR / "results"
PROJECT_ROOT = EVAL_DIR.parent

sys.path.insert(0, str(EVAL_DIR))

from tamper_simulator import run_tamper_simulation, compute_sha256
from detector import run_detection_suite
from metrics_calculator import calculate_detection_rate, calculate_detection_latency, generate_combined_report


def step_tamper(source, artifact_id, num_per_type):
    print("\n" + "=" * 70)
    print("STEP 1: TAMPER SIMULATION")
    print("=" * 70)
    manifest = run_tamper_simulation(source, artifact_id, num_per_type)
    return manifest


def step_detect(manifest_path, artifact_id):
    print("\n" + "=" * 70)
    print("STEP 2: DETECTION SUITE")
    print("=" * 70)
    return run_detection_suite(manifest_path, artifact_id)


def step_detection_rate(detection_results_path):
    print("\n" + "=" * 70)
    print("STEP 3: DETECTION RATE CALCULATION")
    print("=" * 70)
    return calculate_detection_rate(detection_results_path)


def step_latency_monitor(artifact_path, artifact_id, interval, max_polls, tamper_time):
    print("\n" + "=" * 70)
    print("STEP 4: LATENCY MONITORING")
    print("=" * 70)
    from monitor import monitor_polling
    return monitor_polling(artifact_path, artifact_id, interval, max_polls, tamper_time)


def step_detection_latency(monitor_results_path):
    print("\n" + "=" * 70)
    print("STEP 5: DETECTION LATENCY CALCULATION")
    print("=" * 70)
    return calculate_detection_latency(monitor_results_path)


def run_full_evaluation(source, artifact_id, num_per_type, poll_interval, max_polls):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    print("=" * 70)
    print("BLOCKCHAIN ARTIFACT INTEGRITY - EVALUATION SUITE")
    print("=" * 70)
    print(f"  Source artifact: {source}")
    print(f"  Artifact ID:     {artifact_id}")
    print(f"  Tamper variants: {num_per_type} per method")
    print(f"  Poll interval:   {poll_interval}s")
    print(f"  Max polls:       {max_polls}")
    print(f"  Started at:      {timestamp}")
    print("=" * 70)

    # Step 1: Tamper simulation
    manifest = step_tamper(source, artifact_id, num_per_type)
    manifest_path = RESULTS_DIR / "tampered_artifacts" / "tamper_manifest.json"

    # Step 2: Detection suite
    detection_results = step_detect(str(manifest_path), artifact_id)
    latest_detection_file = sorted(RESULTS_DIR.glob("detection_results_*.json"))[-1]

    # Step 3: Detection rate
    detection_rate = step_detection_rate(str(latest_detection_file))

    # Step 4: Latency monitoring with built-in tamper injection
    tampered_dir = RESULTS_DIR / "tampered_artifacts"
    tampered_files = sorted(tampered_dir.glob("tampered_byte_flip_000.tar"))
    if tampered_files:
        tampered_artifact = tampered_files[0]
        print(f"\n  Injecting tampered artifact for latency test: {tampered_artifact.name}")
        original_hash = compute_sha256(source)
        target_hash = compute_sha256(tampered_artifact)

        shutil.copy2(source, source + ".backup")
        shutil.copy2(tampered_artifact, source)
        tamper_time = time.time()
        print(f"  Tamper introduced at: {tamper_time}")

        monitor_log = step_latency_monitor(source, artifact_id, poll_interval, max_polls, tamper_time)

        shutil.copy2(source + ".backup", source)
        os.remove(source + ".backup")
        print(f"  Original artifact restored.")

        latest_monitor_file = sorted(RESULTS_DIR.glob("monitor_results_*.json"))[-1]
    else:
        print("\n  No tampered artifact available for latency test. Skipping.")
        monitor_log = None
        latest_monitor_file = None

    # Step 5: Detection latency
    latency_report = None
    if latest_monitor_file:
        latency_report = step_detection_latency(str(latest_monitor_file))

    # Step 6: Combined report
    print("\n" + "=" * 70)
    print("STEP 6: COMBINED REPORT")
    print("=" * 70)
    combined = generate_combined_report(detection_rate, latency_report or {})

    # Final summary
    print("\n" + "=" * 70)
    print("EVALUATION COMPLETE")
    print("=" * 70)
    dr = combined.get("detection_rate", {}).get("overall", {})
    print(f"  Detection Rate:   {dr.get('detection_rate_percent', 'N/A')}%")
    dl = combined.get("detection_latency", {}).get("latency")
    if dl:
        print(f"  Detection Latency: {dl.get('latency_seconds', 'N/A')}s")
    print(f"  Results directory: {RESULTS_DIR}")
    print("=" * 70)

    return combined


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run full evaluation suite")
    parser.add_argument("--source", required=True, help="Path to source artifact (e.g., note-app.tar)")
    parser.add_argument("--artifact-id", default="notes-app-v1", help="Artifact ID")
    parser.add_argument("--num-per-type", type=int, default=3, help="Tampered copies per method (default: 3)")
    parser.add_argument("--poll-interval", type=float, default=5.0, help="Latency monitor poll interval in seconds")
    parser.add_argument("--max-polls", type=int, default=30, help="Max polls for latency monitor")
    args = parser.parse_args()

    if not Path(args.source).exists():
        print(f"ERROR: Source artifact not found: {args.source}")
        sys.exit(1)

    run_full_evaluation(
        args.source,
        args.artifact_id,
        args.num_per_type,
        args.poll_interval,
        args.max_polls,
    )
