"""
Receives TLS telemetry from sensors, applies simple policy and rate anomaly checks, and forwards to cloud.
Usage:
  python3 gateway.py --cloud-ip <IP> [--cloud-port 8443] [--listen-port 8443] [--policy-refresh 15]
Requirements:
  - gateway.cert.pem, gateway.key.pem, ca.cert.pem in working directory
"""
import ssl
import socket
import threading
import json
import time
import requests
import argparse
import logging
from collections import deque
from datetime import datetime

parser = argparse.ArgumentParser(description="Gateway that accepts sensor telemetry over TLS and forwards to cloud.")
parser.add_argument("--cloud-ip", required=True, help="Cloud policy/ingest service IP")
parser.add_argument("--cloud-port", type=int, default=8443, help="Cloud TLS port")
parser.add_argument("--listen-port", type=int, default=8443, help="Port to accept sensors on")
parser.add_argument("--policy-refresh", type=int, default=15, help="Seconds between policy polls")
parser.add_argument("--ca", default="ca.cert.pem", help="CA cert to verify cloud")
parser.add_argument("--cert", default="gateway.cert.pem", help="Gateway cert for TLS server")
parser.add_argument("--key", default="gateway.key.pem", help="Gateway private key")
args = parser.parse_args()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("gateway")

CLOUD_POLICY_URL = f"https://{args.cloud_ip}:{args.cloud_port}/policy"
CLOUD_INGEST_URL = f"https://{args.cloud_ip}:{args.cloud_port}/ingest"
LISTEN_ADDR = ("0.0.0.0", args.listen_port)

# Rate monitor for anomaly detection
class RateMonitor:
    def __init__(self, window_secs=60, threshold=20):
        self.window = deque()
        self.window_secs = window_secs
        self.threshold = threshold

    def record(self):
        now = time.time()
        self.window.append(now)
        while self.window and self.window[0] < now - self.window_secs:
            self.window.popleft()

    def is_anomalous(self):
        return len(self.window) > self.threshold

rate_monitor = RateMonitor()

# Policy state
current_policy = {
    "allowed_sensors": [],
    "rate_limit_per_minute": 100
}

def fetch_policy():
    global current_policy
    try:
        resp = requests.get(CLOUD_POLICY_URL, verify=args.ca, timeout=5)
        if resp.status_code == 200:
            current_policy = resp.json()
            logger.info(f"Fetched policy: {current_policy}")
        else:
            logger.warning(f"Failed to fetch policy: status {resp.status_code}")
    except Exception as e:
        logger.warning(f"Error fetching policy: {e}")

def policy_refresher():
    while True:
        fetch_policy()
        time.sleep(args.policy_refresh)

def forward_to_cloud(payload):
    try:
        resp = requests.post(CLOUD_INGEST_URL, json=payload, verify=args.ca, timeout=5)
        logger.info(f"Forwarded to cloud: status={resp.status_code}, response={resp.text.strip()}")
    except Exception as e:
        logger.warning(f"Failed forwarding to cloud: {e}")

def handle_client(conn_stream, addr):
    try:
        data = conn_stream.recv(8192)
        if not data:
            return
        try:
            msg = json.loads(data.decode())
        except json.JSONDecodeError:
            logger.warning(f"Malformed JSON from {addr}: {data}")
            conn_stream.send(b'{ "status": "error", "reason": "bad format" }')
            return

        sensor_id = msg.get("sensor_id", "<unknown>")
        if sensor_id not in current_policy.get("allowed_sensors", []):
            logger.warning(f"Sensor {sensor_id} not allowed by policy")
            conn_stream.send(b'{ "status": "rejected", "reason": "not allowed" }')
            return

        rate_monitor.record()
        if rate_monitor.is_anomalous():
            logger.warning("Rate anomaly detected; throttling message")
            conn_stream.send(b'{ "status": "throttled" }')
            return

        forward_to_cloud(msg)
        conn_stream.send(b'{ "status": "accepted" }')
    finally:
        try:
            conn_stream.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        conn_stream.close()

def start_tls_server():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=args.cert, keyfile=args.key)
    bindsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bindsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bindsock.bind(LISTEN_ADDR)
    bindsock.listen(5)
    logger.info(f"Gateway listening on {LISTEN_ADDR} for sensors")
    while True:
        newsock, addr = bindsock.accept()
        try:
            conn_stream = context.wrap_socket(newsock, server_side=True)
            threading.Thread(target=handle_client, args=(conn_stream, addr), daemon=True).start()
        except ssl.SSLError as e:
            logger.warning(f"SSL error during connection from {addr}: {e}")
            newsock.close()

if __name__ == "__main__":
    # Start policy refresher thread
    threading.Thread(target=policy_refresher, daemon=True).start()
    # Initial policy fetch
    fetch_policy()
    start_tls_server()
