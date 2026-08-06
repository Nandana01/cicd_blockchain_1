import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

RESULTS_DIR = Path(__file__).parent / "results"
PROJECT_ROOT = Path(__file__).parent.parent


def check_artifact_integrity(artifact_path, artifact_id):
    helper_script = PROJECT_ROOT / "evaluation" / "_web3_helper.py"
    cmd = [sys.executable, str(helper_script), str(artifact_path), artifact_id]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        stderr = result.stderr or ""

        if "ModuleNotFoundError" in stderr or "ImportError" in stderr:
            return {"status": "ERROR", "reason": "web3 module not available", "is_tampered": None}

        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout.strip())
            if "error" in data:
                return {"status": "ERROR", "reason": data["error"], "is_tampered": None}
            return {
                "status": "TAMPERED" if data.get("detected") else "SECURE",
                "is_tampered": data.get("detected"),
                "computed_hash": data.get("computed_hash"),
            }
        else:
            return {"status": "ERROR", "reason": stderr[:200] if stderr else "no output", "is_tampered": None}
    except subprocess.TimeoutExpired:
        return {"status": "ERROR", "reason": "timeout", "is_tampered": None}
    except Exception as e:
        return {"status": "ERROR", "reason": str(e), "is_tampered": None}


def monitor_polling(artifact_path, artifact_id, interval_seconds, max_polls, tamper_time=None):
    if not Path(artifact_path).exists():
        print(f"ERROR: Artifact not found: {artifact_path}")
        sys.exit(1)

    print(f"Starting monitor: artifact={artifact_path}")
    print(f"  Polling interval: {interval_seconds}s")
    print(f"  Max polls: {max_polls}")
    print(f"  Tamper time (if known): {tamper_time}")
    print()

    log = {
        "artifact_path": str(artifact_path),
        "artifact_id": artifact_id,
        "interval_seconds": interval_seconds,
        "max_polls": max_polls,
        "tamper_time": tamper_time,
        "monitor_start": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "polls": [],
        "detections": [],
    }

    previous_status = None
    tamper_timestamp = tamper_time

    for poll_num in range(1, max_polls + 1):
        check_start = time.time()
        result = check_artifact_integrity(artifact_path, artifact_id)
        check_end = time.time()

        poll_record = {
            "poll_number": poll_num,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "timestamp_unix": round(check_start, 4),
            "status": result["status"],
            "is_tampered": result.get("is_tampered"),
            "check_duration_seconds": round(check_end - check_start, 4),
        }
        log["polls"].append(poll_record)

        status_str = result["status"]
        reason = f" ({result.get('reason', '')})" if result.get("reason") else ""
        print(f"  Poll {poll_num:4d} | {poll_record['timestamp']} | {status_str}{reason}")

        if previous_status == "SECURE" and result["status"] == "TAMPERED":
            detection_record = {
                "detected_at_poll": poll_num,
                "detection_timestamp": poll_record["timestamp"],
                "detection_timestamp_unix": poll_record["timestamp_unix"],
                "previous_status": previous_status,
                "current_status": result["status"],
            }
            if tamper_timestamp:
                latency = poll_record["timestamp_unix"] - tamper_timestamp
                detection_record["latency_seconds"] = round(latency, 4)
                print(f"  *** TAMPERING DETECTED! Latency: {latency:.4f}s ***")
            else:
                print(f"  *** TAMPERING DETECTED! (no tamper timestamp for latency) ***")
            log["detections"].append(detection_record)

        previous_status = result["status"]

        if poll_num < max_polls:
            time.sleep(interval_seconds)

    log["monitor_end"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log["total_polls"] = len(log["polls"])
    log["total_detections"] = len(log["detections"])

    output_path = RESULTS_DIR / f"monitor_results_{interval_seconds}s_{int(time.time())}.json"
    output_path.write_text(json.dumps(log, indent=2), encoding="utf-8")
    print(f"\nMonitor results written: {output_path}")
    return log


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Periodic monitoring for detection latency measurement")
    parser.add_argument("--artifact-path", required=True, help="Path to the artifact to monitor")
    parser.add_argument("--artifact-id", default="notes-app-v1", help="Artifact ID")
    parser.add_argument("--interval", type=float, default=5.0, help="Polling interval in seconds (default: 5)")
    parser.add_argument("--max-polls", type=int, default=60, help="Maximum number of polls (default: 60)")
    parser.add_argument("--tamper-time", type=float, default=None, help="Unix timestamp when tampering was introduced")
    args = parser.parse_args()

    monitor_polling(args.artifact_path, args.artifact_id, args.interval, args.max_polls, args.tamper_time)
