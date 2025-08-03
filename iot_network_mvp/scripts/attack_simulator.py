"""
Simulates security attack scenarios against the gateway in a self-contained way (defaults to localhost) so you can run without supplying external IPs.
Supports:
  * unauthorized: uses a sensor ID not in policy to test rejection
  * malformed: sends non-JSON or missing fields to test input validation
  * rate_flood: floods the gateway with many messages to trigger rate anomaly detection

Outputs test-specific summaries and optionally writes raw interaction logs to an output file.

Usage examples:
  python3 attack_simulator.py --mode unauthorized
  python3 attack_simulator.py --mode malformed
  python3 attack_simulator.py --mode rate_flood --sensor-id sensor-1 --duration 10 --rate 20

All tests default to TLS against localhost:8443. Use --no-tls to avoid certs for isolated unit testing.
"""
import argparse
import ssl
import socket
import json
import time
import random
from datetime import datetime
from statistics import mean

parser = argparse.ArgumentParser(description="Attack scenarios against gateway (unauthorized, malformed, rate_flood)")
parser.add_argument("--gateway-ip", default="localhost", help="Gateway IP (defaults to localhost)")
parser.add_argument("--gateway-port", type=int, default=8443, help="Gateway TLS port")
parser.add_argument("--mode", choices=["unauthorized", "rate_flood", "malformed"], required=True, help="Attack mode to run")
parser.add_argument("--sensor-id", default="sensor-1", help="Legitimate sensor ID for rate_flood/malformed tests")
parser.add_argument("--duration", type=int, default=10, help="Duration in seconds for flooding (rate_flood)")
parser.add_argument("--rate", type=int, default=10, help="Messages per second during flood (rate_flood)")
parser.add_argument("--ca", default="../certs/ca.cert.pem", help="CA certificate to trust for TLS")
parser.add_argument("--disable-hostname-check", action="store_true", help="Skip hostname verification (MVP convenience)")
parser.add_argument("--no-tls", action="store_true", help="Use plaintext TCP instead of TLS (for isolated unit testing without certs)")
parser.add_argument("--output", default=None, help="Optional file path to dump raw output and summary")
args = parser.parse_args()

GATEWAY_ADDR = (args.gateway_ip, args.gateway_port)


def send_message(payload_bytes):
    """Send raw bytes to gateway, over TLS unless --no-tls is set."""
    try:
        sock = socket.create_connection(GATEWAY_ADDR, timeout=3)
        if not args.no_tls:
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=args.ca)
            if args.disable_hostname_check:
                context.check_hostname = False
            conn = context.wrap_socket(sock, server_hostname="gateway.local")
        else:
            conn = sock
        with conn:
            conn.sendall(payload_bytes)
            resp = conn.recv(4096)
        return resp.decode(errors="ignore").strip()
    except Exception as e:
        return f"EXCEPTION: {e}"


def unauthorized_test():
    log_lines = []
    log_lines.append("[*] Unauthorized sensor test (should be rejected by policy)")
    message = {"sensor_id": "sensor-bad", "temperature": 30, "timestamp": datetime.utcnow().isoformat()}
    raw = json.dumps(message).encode()
    resp = send_message(raw)
    log_lines.append(f"Sent payload: {message}")
    log_lines.append(f"Gateway response: {resp}")
    # Simple interpretation
    status = None
    try:
        status = json.loads(resp).get("status")
    except Exception:
        status = resp
    if status and "reject" in str(status).lower():
        log_lines.append("Result: PASS (unauthorized sensor was rejected)")
    else:
        log_lines.append("Result: FAIL (unexpected acceptance or malformed response)")
    return log_lines


def malformed_test():
    log_lines = []
    log_lines.append("[*] Malformed payload test")
    # Non-JSON payload
    resp1 = send_message(b"this-is-not-json")
    log_lines.append("-- Non-JSON test --")
    log_lines.append(f"Sent: this-is-not-json")
    log_lines.append(f"Response: {resp1}")
    # Missing sensor_id
    payload = {"temperature": 25}
    resp2 = send_message(json.dumps(payload).encode())
    log_lines.append("-- Missing sensor_id test --")
    log_lines.append(f"Sent: {payload}")
    log_lines.append(f"Response: {resp2}")
    # Interpretation heuristics
    if ("error" in resp1.lower() or "bad format" in resp1.lower() or "rejected" in resp1.lower()) and (
        "error" in resp2.lower() or "rejected" in resp2.lower() or "throttl" not in resp2.lower()
    ):
        log_lines.append("Result: PASS (malformed inputs handled/rejected)")
    else:
        log_lines.append("Result: WARNING or FAIL (unexpected handling)")
    return log_lines


def rate_flood_test():
    log_lines = []
    log_lines.append("[*] Rate flood test (attempt to trigger throttling/anomaly detection)")
    end = time.time() + args.duration
    count = 0
    responses = []
    throttled_count = 0
    while time.time() < end:
        message = {"sensor_id": args.sensor_id, "temperature": 20 + random.random() * 5, "timestamp": datetime.utcnow().isoformat()}
        resp = send_message(json.dumps(message).encode())
        responses.append(resp)
        if "throttl" in resp.lower():
            throttled_count += 1
        log_lines.append(f"[{count}] Response: {resp}")
        count += 1
        time.sleep(1.0 / args.rate)
    log_lines.append(f"Total messages sent: {count}")
    log_lines.append(f"Throttled responses observed: {throttled_count}")
    if throttled_count > 0:
        log_lines.append("Result: PASS (rate anomaly detection engaged)")
    else:
        log_lines.append("Result: WARNING or FAIL (no throttling observed)")
    # Basic stats
    numeric_resps = []
    for r in responses:
        numeric_resps.append(r)
    return log_lines


def write_output(log_lines):
    out = "\n".join(log_lines)
    print(out)
    if args.output:
        try:
            with open(args.output, "w") as f:
                f.write(out + "\n")
            print(f"[+] Wrote attack log to {args.output}")
        except Exception as e:
            print(f"[!] Failed to write output file: {e}")


def main():
    if args.mode == "unauthorized":
        logs = unauthorized_test()
    elif args.mode == "malformed":
        logs = malformed_test()
    elif args.mode == "rate_flood":
        logs = rate_flood_test()
    else:
        logs = ["Unknown mode"]
    write_output(logs)


if __name__ == "__main__":
    main()
