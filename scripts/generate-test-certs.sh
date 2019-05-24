#!/usr/bin/env bash

# Generate the CA public certificate, CA private key, client public certificate, and client private key
openssl genrsa -des3 -passout pass:test -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 1024 -passin pass:test -subj "/C=US/ST=CA/O=Testing, Inc./CN=test-CA" -out ca.crt
openssl genrsa -out instance.key 2048
openssl req -new -sha256 -key instance.key -out instance.csr -config scripts/openssl.cnf
openssl x509 -req -extfile scripts/openssl.cnf -extensions req_ext -in instance.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out instance.crt -days 500 -sha256 -passin pass:test

# Cleanup unnecessary files
rm ca.key
rm instance.csr
rm ca.srl

# Move the files into testdata
TARGET_DIR="$(pwd)/testdata/fake-certificates"
rm -rf ${TARGET_DIR}
mkdir ${TARGET_DIR}
echo "Placing new, valid ca.crt, instance.crt, and instance.key in $TARGET_DIR"
mv ca.crt ${TARGET_DIR}
mv instance.crt ${TARGET_DIR}
mv instance.key ${TARGET_DIR}

