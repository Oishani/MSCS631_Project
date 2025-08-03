"""
Simulate many sensors sending telemetry concurrently to the gateway to measure scalability.
Defaults to localhost so you can run without providing a gateway IP. Requires the gateway and cloud
policy service to be running locally (or pointed via --gateway-ip/--gateway-port).

Outputs a CSV of per-message results and optionally a summary report.

Usage:
  python3 scaling_test.py [--gateway-ip GATEWAY] [--num-sensors 10] \
        [--messages-per-sensor 20] [--interval 1.0] [--output results.csv] [--summary-output summary.txt]

Example:
  python3 scaling_test.py --num-sensors 5 --messages-per-sensor 50 --interval 0.5 --disable-hostname-check
"""
import argparse
import threading
import ssl
import socket
import json
import time
import random
import csv
from datetime import datetime
from statistics import mean

parser = argparse.ArgumentParser(description="Scalability test: many sensors sending telemetry")
parser.add_argument("--gateway-ip", default="localhost", help="Gateway IP to send telemetry to (defaults to localhost)")
parser.add_argument("--gateway-port", type=int, default=8443, help="Gateway TLS port")
parser.add_argument("--num-sensors", type=int, default=5, help="Number of concurrent simulated sensors")
parser.add_argument("--messages-per-sensor", type=int, default=20, help="Telemetry messages each sensor sends")
parser.add_argument("--interval", type=float, default=1.0, help="Seconds between messages per sensor")
parser.add_argument("--ca", default="../certs/ca.cert.pem", help="Path to CA certificate")
parser.add_argument("--disable-hostname-check", action="store_true", help="Skip hostname verification (MVP convenience)")
parser.add_argument("--output", default="scaling_results.csv", help="CSV output file for results")
parser.add_argument("--summary-output", default=None, help="Optional file to write summary text to")
parser.add_argument("--no-tls", action="store_true", help="Use plaintext TCP instead of TLS (for isolated unit testing without certs)")
args = parser.parse_args()

GATEWAY_ADDR = (args.gateway_ip, args.gateway_port)
lock = threading.Lock()
results = []


def make_connection():
    """Create a socket connected to the gateway; TLS-wrapped unless --no-tls is used."""
    sock = socket.create_connection(GATEWAY_ADDR, timeout=5)
    if args.no_tls:
        return sock  # plaintext
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=args.ca)
    if args.disable_hostname_check:
        context.check_hostname = False
    # wrap the existing socket
    return context.wrap_socket(sock, server_hostname="gateway.local")


def sensor_worker(sensor_id: str):
    for i in range(args.messages_per_sensor):
        payload = {
            "sensor_id": sensor_id,
            "temperature": 20 + random.random() * 10,
            "timestamp": datetime.utcnow().isoformat()
        }
        sent_at_time = datetime.utcnow().isoformat()
        try:
            t0 = time.time()
            with make_connection() as conn:
                conn.sendall(json.dumps(payload).encode())
                resp = conn.recv(4096)
            t1 = time.time()
            latency = t1 - t0
            status = "unknown"
            raw = resp.decode(errors="ignore").strip()
            try:
                resp_json = json.loads(raw)
                status = resp_json.get("status", "none")
            except Exception:
                status = raw or "unparseable"
            with lock:
                results.append({
                    "sensor_id": sensor_id,
                    "msg_index": i,
                    "sent_at": sent_at_time,
                    "latency_secs": latency,
                    "response_raw": raw,
                    "status": status,
                })
        except Exception as e:
            with lock:
                results.append({
                    "sensor_id": sensor_id,
                    "msg_index": i,
                    "sent_at": sent_at_time,
                    "latency_secs": None,
                    "response_raw": str(e),
                    "status": "error",
                })
        time.sleep(args.interval)


def compute_and_print_summary(rows):
    total = len(rows)
    errors = sum(1 for r in rows if r.get("status") == "error" or r.get("latency_secs") in (None, "", "None"))
    per_sensor = {}
    for r in rows:
        sid = r["sensor_id"]
        per_sensor.setdefault(sid, []).append(r)
    lines = []
    lines.append(f"Total messages: {total}")
    lines.append(f"Errors / failures: {errors}")
    lines.append("")
    for sensor_id, entries in sorted(per_sensor.items()):
        latencies = [e.get("latency_secs") for e in entries if isinstance(e.get("latency_secs"), (int, float))]
        success = len([e for e in entries if e.get("status") not in ("error",)])
        count = len(entries)
        if latencies:
            avg_lat = mean(latencies)
            lines.append(f"{sensor_id}: messages={count}, success={success}, avg_latency={avg_lat:.3f}s")
        else:
            lines.append(f"{sensor_id}: messages={count}, success={success}, all failed or no valid latency")
    summary_text = "\n".join(lines)
    print("\n===== SUMMARY =====")
    print(summary_text)
    if args.summary_output:
        try:
            with open(args.summary_output, "w") as f:
                f.write(summary_text + "\n")
            print(f"[+] Summary written to {args.summary_output}")
        except Exception as e:
            print(f"[!] Failed to write summary: {e}")


def main():
    print(f"[+] Starting scalability test: {args.num_sensors} sensors, {args.messages_per_sensor} messages each")
    threads = []
    for n in range(1, args.num_sensors + 1):
        sensor_id = f"sensor-{n}"
        t = threading.Thread(target=sensor_worker, args=(sensor_id,), daemon=True)
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

    # Write CSV
    with open(args.output, "w", newline="") as csvf:
        fieldnames = ["sensor_id", "msg_index", "sent_at", "latency_secs", "response_raw", "status"]
        writer = csv.DictWriter(csvf, fieldnames=fieldnames)
        writer.writeheader()
        for row in results:
            writer.writerow(row)
    print(f"[+] Wrote results to {args.output}")

    # Summary
    compute_and_print_summary(results)


if __name__ == "__main__":
    main()
