"""
Lightweight telemetry sender to gateway over TLS.
Usage:
  python3 sensor.py --gateway-ip <IP> [--gateway-port 8443] [--sensor-id sensor-1] [--interval 5]
Requirements:
  - ca.cert.pem must be present in same directory or provide path via --ca
"""
import ssl
import socket
import json
import time
import random
import argparse
import logging
import os
from datetime import datetime

parser = argparse.ArgumentParser(description="Simulated sensor sending telemetry over TLS to gateway")
parser.add_argument("--gateway-ip", required=True, help="IP address of gateway")
parser.add_argument("--gateway-port", type=int, default=8443, help="Port of gateway TLS listener")
parser.add_argument("--sensor-id", default="sensor-1", help="Unique ID of this sensor")
parser.add_argument("--interval", type=float, default=5.0, help="Seconds between telemetry sends")
parser.add_argument("--ca", default="ca.cert.pem", help="CA certificate to trust")
parser.add_argument("--disable-hostname-check", action="store_true", help="Disable hostname verification (MVP convenience)")
args = parser.parse_args()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

GATEWAY_ADDR = (args.gateway_ip, args.gateway_port)

def send_telemetry():
    temp = 20 + random.random() * 10
    payload = {
        "sensor_id": args.sensor_id,
        "temperature": temp,
        "timestamp": datetime.utcnow().isoformat()
    }
    try:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=args.ca)
        if args.disable_hostname_check:
            context.check_hostname = False
        with socket.create_connection(GATEWAY_ADDR, timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname="gateway.local") as ssock:
                ssock.sendall(json.dumps(payload).encode())
                resp = ssock.recv(4096)
                logging.info(f"Telemetry sent: {payload}, gateway response: {resp.decode().strip()}")
    except Exception as e:
        logging.warning(f"Failed to send telemetry: {e}")

def main():
    logging.info(f"Starting sensor {args.sensor_id}, sending to {GATEWAY_ADDR}")
    while True:
        send_telemetry()
        time.sleep(args.interval)

if __name__ == "__main__":
    main()
