import hashlib
import json
import os
import random
import shutil
import string
import sys
import time
from pathlib import Path

RESULTS_DIR = Path(__file__).parent / "results"


def compute_sha256(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def tamper_byte_flip(file_path):
    data = bytearray(Path(file_path).read_bytes())
    pos = random.randint(0, len(data) - 1)
    data[pos] ^= 0x01
    return bytes(data), f"byte_flip@{pos}"


def tamper_overwrite(file_path):
    data = bytearray(Path(file_path).read_bytes())
    overwrite_len = min(64, len(data))
    start = random.randint(0, len(data) - overwrite_len)
    new_bytes = bytes(random.getrandbits(8) for _ in range(overwrite_len))
    data[start:start + overwrite_len] = new_bytes
    return bytes(data), f"overwrite@{start}:{start + overwrite_len}"


def tamper_truncate(file_path):
    data = Path(file_path).read_bytes()
    truncate_at = max(1, len(data) - random.randint(1, min(128, len(data) - 1)))
    return data[:truncate_at], f"truncate@{truncate_at}"


def tamper_append(file_path):
    data = Path(file_path).read_bytes()
    suffix = bytes(random.getrandbits(8) for _ in range(random.randint(1, 64)))
    return data + suffix, f"append_{len(suffix)}_bytes"


def tamper_replace_all(file_path):
    size = Path(file_path).stat().st_size
    return os.urandom(size), "replace_all"


def tamper_same_content_different_name(file_path, dest_path):
    shutil.copy2(file_path, dest_path)
    return dest_path


TAMPER_METHODS = {
    "byte_flip": tamper_byte_flip,
    "overwrite": tamper_overwrite,
    "truncate": tamper_truncate,
    "append": tamper_append,
    "replace_all": tamper_replace_all,
}


def run_tamper_simulation(source_artifact, artifact_id, num_per_type=3, output_dir=None):
    if output_dir is None:
        output_dir = RESULTS_DIR / "tampered_artifacts"
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if not Path(source_artifact).exists():
        print(f"ERROR: Source artifact not found: {source_artifact}")
        sys.exit(1)

    original_hash = compute_sha256(source_artifact)
    print(f"Source artifact: {source_artifact}")
    print(f"Original SHA-256: {original_hash}")
    print(f"Creating {num_per_type} tampered variants per method...")
    print()

    manifest = {
        "source_artifact": str(source_artifact),
        "artifact_id": artifact_id,
        "original_hash": original_hash,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "tampered_artifacts": [],
    }

    for method_name, method_fn in TAMPER_METHODS.items():
        for i in range(num_per_type):
            tag = f"{method_name}_{i:03d}"
            out_file = output_dir / f"tampered_{tag}.tar"

            if method_name == "append":
                tampered_data, description = method_fn(source_artifact)
            else:
                tampered_data, description = method_fn(source_artifact)

            Path(out_file).write_bytes(tampered_data)
            tampered_hash = compute_sha256(out_file)

            record = {
                "filename": f"tampered_{tag}.tar",
                "filepath": str(out_file),
                "tamper_method": method_name,
                "tamper_index": i,
                "description": description,
                "tampered_hash": tampered_hash,
                "hash_differs": tampered_hash != original_hash,
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            manifest["tampered_artifacts"].append(record)
            print(f"  [{tag}] method={method_name}  hash={tampered_hash[:16]}...  diff={tampered_hash != original_hash}")

    manifest_path = output_dir / "tamper_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"\nManifest written: {manifest_path}")
    print(f"Total tampered artifacts: {len(manifest['tampered_artifacts'])}")
    return manifest


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Generate tampered artifact variants for detection rate evaluation")
    parser.add_argument("--source", required=True, help="Path to the source artifact (e.g., note-app.tar)")
    parser.add_argument("--artifact-id", default="notes-app-v1", help="Artifact ID (default: notes-app-v1)")
    parser.add_argument("--num-per-type", type=int, default=3, help="Number of tampered copies per method (default: 3)")
    parser.add_argument("--output-dir", default=None, help="Output directory for tampered artifacts")
    args = parser.parse_args()

    run_tamper_simulation(args.source, args.artifact_id, args.num_per_type, args.output_dir)
