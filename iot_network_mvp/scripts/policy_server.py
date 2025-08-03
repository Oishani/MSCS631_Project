"""
Simple Flask service that exposes a policy and accepts telemetry ingestion over TLS.
Usage:
  python3 policy_server.py [--port 8443] [--allowed-sensors sensor-1,sensor-2] [--rate-limit 10]
Requirements:
  - cloud.cert.pem, cloud.key.pem and ca.cert.pem present in working directory
"""
import argparse
import logging
import json
from flask import Flask, request, jsonify
from datetime import datetime

parser = argparse.ArgumentParser(description="Cloud policy and ingestion service")
parser.add_argument("--port", type=int, default=8443, help="TLS port to serve on")
parser.add_argument("--allowed-sensors", default="sensor-1,sensor-2", help="Comma-separated allowed sensor IDs")
parser.add_argument("--rate-limit", type=int, default=10, help="Rate limit per minute (used for documentation)")
args = parser.parse_args()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
app = Flask(__name__)

POLICY = {
    "allowed_sensors": args.allowed_sensors.split(","),
    "rate_limit_per_minute": args.rate_limit
}

@app.route("/policy", methods=["GET"])
def get_policy():
    return jsonify(POLICY)

@app.route("/ingest", methods=["POST"])
def ingest():
    data = request.get_json()
    logging.info(f"Telemetry ingested: {json.dumps(data)}")
    sensor_id = data.get("sensor_id")
    if sensor_id not in POLICY["allowed_sensors"]:
        return jsonify({"status": "rejected", "reason": "sensor not allowed"}), 403
    return jsonify({"status": "accepted", "received_at": datetime.utcnow().isoformat()})

if __name__ == "__main__":
    context = ( "cloud.cert.pem", "cloud.key.pem" )
    app.run(host="0.0.0.0", port=args.port, ssl_context=context)
