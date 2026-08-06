import hashlib
import json
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent


def compute_sha256(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def verify(artifact_path, artifact_id):
    from web3 import Web3

    node_url = os.getenv("ETH_NODE_URL", "http://127.0.0.1:7545")
    w3 = Web3(Web3.HTTPProvider(node_url))
    if not w3.is_connected():
        print(json.dumps({"detected": False, "error": "Cannot connect to Ethereum node"}))
        return

    addr_file = Path(r"C:\Users\ushus\OneDrive - National College of Ireland\Desktop\Full_code\contract_address.json")
    abi_file = Path(r"C:\Users\ushus\OneDrive - National College of Ireland\Desktop\Full_code\contract_abi.json")
    if not addr_file.exists() or not abi_file.exists():
        print(json.dumps({"detected": False, "error": "Contract files not found"}))
        return

    address = json.loads(addr_file.read_text(encoding="utf-8")).get("contract_address")
    abi = json.loads(abi_file.read_text(encoding="utf-8")).get("abi")
    contract = w3.eth.contract(address=address, abi=abi)

    artifact_hash = compute_sha256(artifact_path)
    is_valid = contract.functions.verifyArtifact(artifact_id, artifact_hash).call()
    record = contract.functions.getArtifact(artifact_id).call()

    print(json.dumps({
        "detected": not is_valid,
        "is_valid": is_valid,
        "computed_hash": artifact_hash,
        "stored_hash": record[1],
    }))


if __name__ == "__main__":
    artifact_path = sys.argv[1]
    artifact_id = sys.argv[2]
    verify(artifact_path, artifact_id)
