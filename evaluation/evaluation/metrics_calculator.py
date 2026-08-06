import json
import sys
from pathlib import Path
from collections import defaultdict

RESULTS_DIR = Path(__file__).parent / "results"


def calculate_detection_rate(detection_results_path):
    data = json.loads(Path(detection_results_path).read_text(encoding="utf-8"))
    detections = data.get("detections", [])

    if not detections:
        print("No detection records found.")
        return {}

    by_method = defaultdict(lambda: {"total": 0, "detected": 0, "missed": 0})
    by_pathway = defaultdict(lambda: {"total": 0, "detected": 0, "missed": 0})

    total = len(detections)
    total_detected = 0
    total_missed = 0

    for d in detections:
        method = d.get("tamper_method", "unknown")
        by_method[method]["total"] += 1
        if d["detected_by_count"] > 0:
            by_method[method]["detected"] += 1
            total_detected += 1
        else:
            by_method[method]["missed"] += 1
            total_missed += 1

        for pathway_key in ["verify_script", "web3_direct", "audit_api"]:
            pw = d.get(pathway_key, {})
            pw_name = pw.get("pathway", pathway_key)
            by_pathway[pw_name]["total"] += 1
            if pw.get("detected", False):
                by_pathway[pw_name]["detected"] += 1
            else:
                by_pathway[pw_name]["missed"] += 1

    report = {
        "overall": {
            "total_artifacts": total,
            "detected": total_detected,
            "missed": total_missed,
            "detection_rate_percent": round(total_detected / total * 100, 2) if total > 0 else 0,
        },
        "by_tamper_method": {},
        "by_pathway": {},
    }

    print("=" * 70)
    print("DETECTION RATE REPORT")
    print("=" * 70)
    print(f"\nOverall Detection Rate: {report['overall']['detection_rate_percent']}%")
    print(f"  Total artifacts tested: {total}")
    print(f"  Detected: {total_detected}")
    print(f"  Missed:   {total_missed}")

    print(f"\n--- By Tamper Method ---")
    for method, counts in sorted(by_method.items()):
        rate = round(counts["detected"] / counts["total"] * 100, 2) if counts["total"] > 0 else 0
        report["by_tamper_method"][method] = {
            "total": counts["total"],
            "detected": counts["detected"],
            "missed": counts["missed"],
            "detection_rate_percent": rate,
        }
        print(f"  {method:20s}: {rate:6.2f}%  ({counts['detected']}/{counts['total']})")

    print(f"\n--- By Detection Pathway ---")
    for pathway, counts in sorted(by_pathway.items()):
        rate = round(counts["detected"] / counts["total"] * 100, 2) if counts["total"] > 0 else 0
        report["by_pathway"][pathway] = {
            "total": counts["total"],
            "detected": counts["detected"],
            "missed": counts["missed"],
            "detection_rate_percent": rate,
        }
        print(f"  {pathway:30s}: {rate:6.2f}%  ({counts['detected']}/{counts['total']})")

    print()
    return report


def calculate_detection_latency(monitor_results_path):
    data = json.loads(Path(monitor_results_path).read_text(encoding="utf-8"))
    polls = data.get("polls", [])
    tamper_time = data.get("tamper_time")

    if not polls:
        print("No poll records found.")
        return {}

    intervals = []
    for i in range(1, len(polls)):
        prev = polls[i - 1]
        curr = polls[i]
        intervals.append({
            "poll_from": prev["poll_number"],
            "poll_to": curr["poll_number"],
            "interval_seconds": round(curr["timestamp_unix"] - prev["timestamp_unix"], 4),
            "status_change": prev["status"] != curr["status"],
            "from_status": prev["status"],
            "to_status": curr["status"],
        })

    status_changes = [iv for iv in intervals if iv["status_change"]]

    latency_data = None
    if tamper_time and polls:
        for poll in polls:
            if poll.get("is_tampered") is True:
                latency_seconds = poll["timestamp_unix"] - tamper_time
                latency_data = {
                    "tamper_time_unix": tamper_time,
                    "first_detection_poll": poll["poll_number"],
                    "first_detection_time": poll["timestamp"],
                    "first_detection_time_unix": poll["timestamp_unix"],
                    "latency_seconds": round(latency_seconds, 4),
                    "polling_interval_seconds": data.get("interval_seconds"),
                }
                break

    report = {
        "total_polls": len(polls),
        "total_status_changes": len(status_changes),
        "status_changes": status_changes,
        "latency": latency_data,
        "polling_interval_seconds": data.get("interval_seconds"),
    }

    print("=" * 70)
    print("DETECTION LATENCY REPORT")
    print("=" * 70)
    print(f"\nPolling interval: {data.get('interval_seconds')}s")
    print(f"Total polls: {len(polls)}")
    print(f"Status changes observed: {len(status_changes)}")

    if status_changes:
        print("\nStatus transitions:")
        for sc in status_changes:
            print(f"  Poll {sc['poll_from']} -> {sc['poll_to']}: {sc['from_status']} -> {sc['to_status']}")

    if latency_data:
        print(f"\nDetection Latency: {latency_data['latency_seconds']}s")
        print(f"  Tamper time:       {latency_data['tamper_time_unix']}")
        print(f"  Detection time:    {latency_data['first_detection_time']}")
        print(f"  Detected at poll:  #{latency_data['first_detection_poll']}")
    else:
        print("\nNo tampering detection observed or tamper_time not provided.")

    print()
    return report


def generate_combined_report(detection_report, latency_report, output_path=None):
    combined = {
        "detection_rate": detection_report,
        "detection_latency": latency_report,
    }

    if output_path is None:
        output_path = RESULTS_DIR / "evaluation_report.json"

    Path(output_path).write_text(json.dumps(combined, indent=2), encoding="utf-8")
    print(f"Combined report written: {output_path}")
    return combined


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Calculate detection rate and detection latency metrics")
    subparsers = parser.add_subparsers(dest="command", required=True)

    dr_parser = subparsers.add_parser("detection-rate", help="Calculate detection rate from detection results")
    dr_parser.add_argument("--results", required=True, help="Path to detection_results JSON file")

    dl_parser = subparsers.add_parser("detection-latency", help="Calculate detection latency from monitor results")
    dl_parser.add_argument("--results", required=True, help="Path to monitor_results JSON file")

    combined_parser = subparsers.add_parser("combined", help="Generate combined report")
    combined_parser.add_argument("--detection-results", required=True, help="Detection results JSON")
    combined_parser.add_argument("--latency-results", required=True, help="Monitor results JSON")
    combined_parser.add_argument("--output", default=None, help="Output path for combined report")

    args = parser.parse_args()

    if args.command == "detection-rate":
        calculate_detection_rate(args.results)
    elif args.command == "detection-latency":
        calculate_detection_latency(args.results)
    elif args.command == "combined":
        dr = calculate_detection_rate(args.detection_results)
        dl = calculate_detection_latency(args.latency_results)
        generate_combined_report(dr, dl, args.output)
