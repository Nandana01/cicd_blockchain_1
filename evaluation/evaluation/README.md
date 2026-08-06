# Evaluation Suite: Detection Rate & Detection Latency Metrics

## Prerequisites (Install Before Running)

```bash
pip install web3 py-solc-x Flask Werkzeug
```

| Package | Required By | Purpose |
|---------|-------------|---------|
| `web3` | verify_artifact.py, audit_app.py, detector.py, monitor.py | Ethereum blockchain interaction |
| `py-solc-x` | deploy_contract.py | Solidity contract compilation |
| `Flask` | app.py, audit_app.py | Web application framework |
| `Werkzeug` | Flask dependency | WSGI utilities |

### Infrastructure Requirements

| Requirement | Details |
|-------------|---------|
| Ganache | Local Ethereum node running at `http://127.0.0.1:7545` |
| Docker | For building container images |
| Docker Compose | For container orchestration |
| PowerShell | For pipeline.ps1 execution |
| Python 3.10+ | Runtime environment |

### Environment Variables

```bash
set ETH_ACCOUNT_ADDRESS=0xYourAccountAddress
set ETH_PRIVATE_KEY=your_private_key
set ETH_NODE_URL=http://127.0.0.1:7545    # optional, defaults to Ganache
```

### Pre-Run Checklist

1. Ganache is running and accessible
2. Smart contract is deployed (`contract_address.json` and `contract_abi.json` exist)
3. A verified artifact exists on the blockchain (run `pipeline.ps1` once)
4. All Python packages installed (`pip install -r requirements.txt`)

## Quick Start

```bash
cd evaluation
python run_evaluation.py --source ../note-app.tar --artifact-id notes-app-v1
```

## Individual Steps

```bash
# Step 1: Generate tampered artifacts
python tamper_simulator.py --source ../note-app.tar --artifact-id notes-app-v1 --num-per-type 5

# Step 2: Run detection on tampered artifacts
python detector.py results/tampered_artifacts/tamper_manifest.json --artifact-id notes-app-v1

# Step 3: Calculate detection rate
python metrics_calculator.py detection-rate --results results/detection_results_*.json

# Step 4: Run latency monitoring
python monitor.py --artifact-path ../note-app.tar --artifact-id notes-app-v1 --interval 5 --max-polls 30

# Step 5: Calculate detection latency
python metrics_calculator.py detection-latency --results results/monitor_results_*.json
```

## Tamper Methods

| Method | Description |
|--------|-------------|
| `byte_flip` | Flips a single bit in the file |
| `overwrite` | Replaces a random section with random bytes |
| `truncate` | Removes bytes from the end |
| `append` | Adds random bytes to the end |
| `replace_all` | Replaces entire file content |

## Detection Pathways

| Pathway | Description |
|---------|-------------|
| `verify_artifact_script` | CLI verification via `verify_artifact.py` subprocess |
| `web3_direct` | Direct Web3.py call to smart contract via helper script |
| `audit_api_current_status` | Audit dashboard `/api/current-status` endpoint |

## Output Files

| File | Description |
|------|-------------|
| `results/tamper_manifest.json` | Generated tampered artifacts list |
| `results/detection_results_*.json` | Per-artifact detection results |
| `results/monitor_results_*.json` | Periodic polling log |
| `results/verification_log.jsonl` | Append-only verification call log |
| `results/evaluation_report.json` | Combined report |

## Metrics

**Detection Rate:**
```
Detection Rate = (Correctly Detected / Total Tampered) x 100%
```

**Detection Latency:**
```
Latency = Detection Timestamp - Tamper Introduction Timestamp
```
