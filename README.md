# Phase 2 Simulation MVP (with Scalability & Security Tests)

## Overview
This minimal viable implementation realizes the Phase 1 architecture in a simulated environment (GNS3 or equivalent Linux VMs) and includes:
- Secure telemetry flow: Sensor → Gateway → Cloud over **TLS**.  
- Policy enforcement and rate-anomaly detection at the Gateway.  
- Cloud-side policy endpoint and ingestion service with allowlist validation.  
- Firewall segmentation restricting flows.  
- **Scalability testing** via many concurrent sensors.  
- **Security testing** including unauthorized access, malformed input, and rate flood simulation.

## Requirements
- Linux VMs (e.g., Ubuntu 22.04+) for each role: sensor, gateway, cloud (firewall can be separate or baked into gateway path).  
- Python 3.8+  
- OpenSSL, iptables, and basic networking utilities.  
- No Docker required for MVP.  
- Wireshark/tshark for captures.

## Directory Structure
```
phase2_simulation_mvp/
├── certs_generate.sh               # Generates CA and TLS certificates
├── firewall_setup.sh              # iptables segmentation script
├── scripts/
│   ├── sensor.py                 # IoT sensor telemetry sender over TLS
│   ├── gateway.py                # Gateway: TLS server, policy polling, anomaly detection, forwarding
│   ├── policy_server.py          # Cloud policy + telemetry ingestion service over TLS
│   ├── scaling_test.py           # Scalability harness (many sensors)
│   ├── attack_simulator.py       # Security attack scenarios (unauthorized, malformed, rate flood)
│   └── analyze_results.py        # Post-process scaling CSV to summary stats
├── certs/                        # Certificates (after running generator)
├── .gitignore
README.md
```

## Step-by-step Setup

### 1. Generate Certificates (shared PKI)
Run once on any machine, then copy appropriate certs to each role:
```bash
chmod +x certs_generate.sh
./certs_generate.sh
```
Produces under `certs/`:
- `ca.cert.pem` – root CA  
- `gateway.cert.pem` / `gateway.key.pem`  
- `cloud.cert.pem` / `cloud.key.pem`  
- `sensor.cert.pem` / `sensor.key.pem` (optional client cert)

Distribute:
- **Sensor VM:** `ca.cert.pem`  
- **Gateway VM:** `gateway.cert.pem`, `gateway.key.pem`, `ca.cert.pem`  
- **Cloud VM:** `cloud.cert.pem`, `cloud.key.pem`, `ca.cert.pem`

### 2. Start Core Services

#### Cloud Policy & Ingest Service
On the cloud VM:
```bash
cd phase2_simulation_mvp/scripts
# Example: allow sensors 1..5
python3 policy_server.py --allowed-sensors sensor-1,sensor-2,sensor-3,sensor-4,sensor-5 --rate-limit 10
```
Listens at `https://0.0.0.0:8443` over TLS. Ensure `cloud.cert.pem`, `cloud.key.pem`, and `ca.cert.pem` are in the working directory.

#### Gateway
On the gateway VM (replace `<CLOUD_IP>` with the cloud VM’s IP):
```bash
cd phase2_simulation_mvp/scripts
python3 gateway.py --cloud-ip <CLOUD_IP> --policy-refresh 15
```
Requires `gateway.cert.pem`, `gateway.key.pem`, and `ca.cert.pem` in place.

#### Sensor
On the sensor VM (replace `<GATEWAY_IP>` with the gateway IP):
```bash
cd phase2_simulation_mvp/scripts
python3 sensor.py --gateway-ip <GATEWAY_IP> --sensor-id sensor-1 --interval 5 --disable-hostname-check
```
Ensure `ca.cert.pem` is present. `--disable-hostname-check` is acceptable for MVP to avoid hostname mismatches.

### 3. Apply Firewall Rules (optional/separate firewall VM)
```bash
sudo ./firewall_setup.sh <GATEWAY_IP> <CLOUD_IP>
```
Restricts forwarding so only TLS (port 8443) traffic between gateway and cloud is allowed.

## Scalability Testing
Simulate many concurrent sensors and measure performance.

### Run the test
1. Ensure the cloud policy server’s `--allowed-sensors` includes all sensors you will simulate (e.g., `sensor-1` through `sensor-10`).  
2. Run:
   ```bash
   cd phase2_simulation_mvp/scripts
   python3 scaling_test.py --gateway-ip <GATEWAY_IP> --num-sensors 10 --messages-per-sensor 50 --interval 0.5 --disable-hostname-check --output ../scaling_results.csv
   ```
3. Summarize:
   ```bash
   python3 analyze_results.py --input ../scaling_results.csv > ../results/summary.txt
   ```

### Output
- `scaling_results.csv`: per-message latency, status, timestamp.  
- Summary (via `analyze_results.py`): success counts and average latency per sensor.

## Security Testing
Simulate key attacks and verify countermeasures.

### Unauthorized Access
```bash
python3 attack_simulator.py --gateway-ip <GATEWAY_IP> --mode unauthorized --disable-hostname-check
```
Expected: rejection; gateway logs and response indicate “not allowed”.

### Malformed Payloads
```bash
python3 attack_simulator.py --gateway-ip <GATEWAY_IP> --mode malformed --disable-hostname-check
```
Expected: gateway handles invalid JSON and missing fields gracefully, logging warnings.

### Rate Flood (Anomaly Detection)
```bash
python3 attack_simulator.py --gateway-ip <GATEWAY_IP> --mode rate_flood --sensor-id sensor-1 --duration 20 --rate 30 --disable-hostname-check
```
Expected: gateway detects high message rate and throttles, logging anomaly warnings, responses indicating throttling.

## Expected Behavior Summary
- Secure TLS connections on port 8443 for all telemetry and policy interactions.  
- Gateway only accepts allowed sensor IDs per policy.  
- Gateway applies rate-based throttling when thresholds are exceeded.  
- Cloud ingests only valid, policy-compliant telemetry.  
- Unauthorized/malformed inputs are rejected or logged appropriately.  
- Firewall enforces segmentation, limiting traffic to intended flows.

## Troubleshooting
- **TLS errors:** verify that `ca.cert.pem` is used by clients and server certs are in place; use `--disable-hostname-check` for MVP if CN mismatches.  
- **Policy not updating:** ensure gateway can reach cloud and that network connectivity (firewall, routing) allows HTTPS.  
- **Telemetry failures:** check gateway logs for rate anomalies or policy rejections.  
- **Firewall blocking:** temporarily flush (`sudo iptables -F`) to isolate connectivity issues.