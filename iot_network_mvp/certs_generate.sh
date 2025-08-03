#!/bin/bash
set -e

# This script generates a self-signed CA and signs server certificates for gateway and cloud.
# It also generates an optional client cert for sensor for future mutual TLS extension.
# Outputs in certs/ directory.

mkdir -p certs
cd certs

echo "[*] Generating CA key and certificate..."
openssl genrsa -out ca.key.pem 2048
openssl req -x509 -new -nodes -key ca.key.pem -sha256 -days 3650 \
  -subj "/C=US/ST=State/L=City/O=Org/OU=IoT/CN=IoT-CA" -out ca.cert.pem

echo "[*] Generating Gateway key and CSR..."
openssl genrsa -out gateway.key.pem 2048
openssl req -new -key gateway.key.pem \
  -subj "/C=US/ST=State/L=City/O=Gateway/OU=IoT/CN=gateway.local" -out gateway.csr.pem
echo "[*] Signing Gateway certificate with CA..."
openssl x509 -req -in gateway.csr.pem -CA ca.cert.pem -CAkey ca.key.pem -CAcreateserial \
  -out gateway.cert.pem -days 365 -sha256

echo "[*] Generating Cloud key and CSR..."
openssl genrsa -out cloud.key.pem 2048
openssl req -new -key cloud.key.pem \
  -subj "/C=US/ST=State/L=City/O=Cloud/OU=IoT/CN=cloud.local" -out cloud.csr.pem
echo "[*] Signing Cloud certificate with CA..."
openssl x509 -req -in cloud.csr.pem -CA ca.cert.pem -CAkey ca.key.pem -CAcreateserial \
  -out cloud.cert.pem -days 365 -sha256

echo "[*] (Optional) Generating Sensor client certificate..."
openssl genrsa -out sensor.key.pem 2048
openssl req -new -key sensor.key.pem \
  -subj "/C=US/ST=State/L=City/O=Sensor/OU=IoT/CN=sensor.local" -out sensor.csr.pem
openssl x509 -req -in sensor.csr.pem -CA ca.cert.pem -CAkey ca.key.pem -CAcreateserial \
  -out sensor.cert.pem -days 365 -sha256

echo "[+] Certificate generation complete. Files in $(pwd):"
ls -1 *.pem
