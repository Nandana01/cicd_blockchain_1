import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

RESULTS_DIR = Path(__file__).parent / "results"
PROJECT_ROOT = Path(__file__).parent.parent


def compute_sha256(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def detect_via_verify_script(artifact_path, artifact_id):
    verify_script = PROJECT_ROOT / "verify_artifact.py"
    cmd = [
        sys.executable, str(verify_script),
        "--artifact-path", str(artifact_path),
        "--artifact-id", artifact_id,
    ]
    start = time.time()
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        elapsed = time.time() - start
        stderr = result.stderr or ""
        stdout = result.stdout or ""

        is_import_error = "ModuleNotFoundError" in stderr or "ImportError" in stderr
        is_verification_failed = "VERIFICATION FAILED" in stdout
        is_verification_passed = "VERIFICATION PASSED" in stdout

        if is_import_error:
            return {
                "pathway": "verify_artifact_script",
                "detected": False,
                "exit_code": result.returncode,
                "elapsed_seconds": round(elapsed, 4),
                "error": "web3 module not available in this Python environment",
                "stderr_snippet": stderr[:300],
            }
        elif is_verification_failed:
            return {
                "pathway": "verify_artifact_script",
                "detected": True,
                "exit_code": result.returncode,
                "elapsed_seconds": round(elapsed, 4),
                "stdout_snippet": stdout[-300:],
            }
        elif is_verification_passed:
            return {
                "pathway": "verify_artifact_script",
                "detected": False,
                "exit_code": result.returncode,
                "elapsed_seconds": round(elapsed, 4),
                "stdout_snippet": stdout[-300:],
            }
        else:
            return {
                "pathway": "verify_artifact_script",
                "detected": result.returncode != 0,
                "exit_code": result.returncode,
                "elapsed_seconds": round(elapsed, 4),
                "stdout_snippet": stdout[-300:],
                "stderr_snippet": stderr[:300],
            }
    except subprocess.TimeoutExpired:
        elapsed = time.time() - start
        return {
            "pathway": "verify_artifact_script",
            "detected": False,
            "exit_code": -1,
            "elapsed_seconds": round(elapsed, 4),
            "error": "timeout",
        }
    except Exception as e:
        elapsed = time.time() - start
        return {
            "pathway": "verify_artifact_script",
            "detected": False,
            "exit_code": -1,
            "elapsed_seconds": round(elapsed, 4),
            "error": str(e),
        }


def detect_via_web3_direct(artifact_path, artifact_id):
    helper_script = PROJECT_ROOT / "evaluation" / "_web3_helper.py"
    cmd = [sys.executable, str(helper_script), str(artifact_path), artifact_id]
    start = time.time()
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        elapsed = time.time() - start
        stderr = result.stderr or ""

        if "ModuleNotFoundError" in stderr or "ImportError" in stderr:
            return {
                "pathway": "web3_direct",
                "detected": False,
                "error": "web3 module not available in this Python environment",
                "elapsed_seconds": round(elapsed, 4),
            }

        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout.strip())
            return {
                "pathway": "web3_direct",
                "detected": data.get("detected", False),
                "is_valid": data.get("is_valid"),
                "computed_hash": data.get("computed_hash"),
                "stored_hash": data.get("stored_hash"),
                "elapsed_seconds": round(elapsed, 4),
            }
        else:
            return {
                "pathway": "web3_direct",
                "detected": False,
                "error": stderr[:300] if stderr else "No output from helper",
                "exit_code": result.returncode,
                "elapsed_seconds": round(elapsed, 4),
            }
    except subprocess.TimeoutExpired:
        elapsed = time.time() - start
        return {
            "pathway": "web3_direct",
            "detected": False,
            "error": "timeout",
            "elapsed_seconds": round(elapsed, 4),
        }
    except Exception as e:
        elapsed = time.time() - start
        return {
            "pathway": "web3_direct",
            "detected": False,
            "error": str(e),
            "elapsed_seconds": round(elapsed, 4),
        }


def detect_via_audit_api(artifact_path, artifact_id=None):
    import urllib.request
    import urllib.error

    audit_url = os.getenv("AUDIT_APP_URL", "http://127.0.0.1:5001")
    start = time.time()

    try:
        req = urllib.request.Request(f"{audit_url}/api/current-status")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            elapsed = time.time() - start
            return {
                "pathway": "audit_api_current_status",
                "detected": data.get("is_valid") is False and data.get("found") is True,
                "status": data.get("status"),
                "is_valid": data.get("is_valid"),
                "elapsed_seconds": round(elapsed, 4),
            }
    except (urllib.error.URLError, ConnectionRefusedError, OSError):
        elapsed = time.time() - start
        return {
            "pathway": "audit_api_current_status",
            "detected": False,
            "error": "Audit app not reachable (port 5001)",
            "elapsed_seconds": round(elapsed, 4),
        }
    except Exception as e:
        elapsed = time.time() - start
        return {
            "pathway": "audit_api_current_status",
            "detected": False,
            "error": str(e),
            "elapsed_seconds": round(elapsed, 4),
        }


def run_detection_suite(tamper_manifest_path, artifact_id=None):
    manifest = json.loads(Path(tamper_manifest_path).read_text(encoding="utf-8"))
    if artifact_id is None:
        artifact_id = manifest.get("artifact_id", "notes-app-v1")

    results = {
        "manifest": str(tamper_manifest_path),
        "artifact_id": artifact_id,
        "source_hash": manifest.get("original_hash"),
        "run_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "detections": [],
    }

    tampered_files = manifest.get("tampered_artifacts", [])
    total = len(tampered_files)
    print(f"Running detection on {total} tampered artifacts...")
    print()

    for idx, entry in enumerate(tampered_files):
        filepath = entry["filepath"]
        method = entry["tamper_method"]
        print(f"  [{idx + 1}/{total}] {entry['filename']} (method={method})", end=" ... ")

        det_result = {
            "filename": entry["filename"],
            "filepath": filepath,
            "tamper_method": method,
            "tampered_hash": entry["tampered_hash"],
            "hash_differs": entry["hash_differs"],
        }

        det_start = time.time()

        r1 = detect_via_verify_script(filepath, artifact_id)
        det_result["verify_script"] = r1

        r2 = detect_via_web3_direct(filepath, artifact_id)
        det_result["web3_direct"] = r2

        r3 = detect_via_audit_api(filepath, artifact_id)
        det_result["audit_api"] = r3

        det_result["total_elapsed_seconds"] = round(time.time() - det_start, 4)

        active_pathways = [r1, r2, r3]
        detected_count = sum(1 for r in active_pathways if r.get("detected", False))
        available_count = sum(1 for r in active_pathways if "error" not in r)
        det_result["detected_by_count"] = detected_count
        det_result["available_pathways"] = available_count
        det_result["detected_by_all"] = detected_count == available_count and available_count > 0

        results["detections"].append(det_result)

        status = "DETECTED" if detected_count > 0 else "MISSED"
        err_parts = []
        if "error" in r1:
            err_parts.append(f"script:{r1['error'][:30]}")
        if "error" in r2:
            err_parts.append(f"web3:{r2['error'][:30]}")
        if "error" in r3:
            err_parts.append(f"api:{r3['error'][:30]}")
        err_str = f" [{', '.join(err_parts)}]" if err_parts else ""
        print(f"{status} ({detected_count}/{available_count} pathways){err_str}")

    detected_total = sum(1 for d in results["detections"] if d["detected_by_count"] > 0)
    results["summary"] = {
        "total_artifacts": total,
        "detected": detected_total,
        "missed": total - detected_total,
        "detection_rate": round(detected_total / total * 100, 2) if total > 0 else 0,
    }

    output_path = RESULTS_DIR / f"detection_results_{int(time.time())}.json"
    output_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nDetection results written: {output_path}")
    print(f"Detection rate: {results['summary']['detection_rate']}%")
    return results


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run detection suite against tampered artifacts")
    parser.add_argument("--manifest", required=True, help="Path to tamper_manifest.json")
    parser.add_argument("--artifact-id", default=None, help="Artifact ID override")
    args = parser.parse_args()

    run_detection_suite(args.manifest, args.artifact_id)
