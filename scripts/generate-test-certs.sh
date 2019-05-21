#!/usr/bin/env bash

# Generate the CA public certificate, CA private key, client public certificate, and client private key
openssl genrsa -des3 -passout pass:test -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 1024 -passin pass:test -subj "/C=US/ST=CA/O=Testing, Inc./CN=test-CA" -out ca.crt
openssl genrsa -out instance.key 2048
openssl req -new -sha256 -key instance.key -subj "/C=US/ST=CA/O=MyOrg, Inc./CN=1bf2e7f6-2d1d-41ec-501c-c70/OU=organization:34a878d0-c2f9-4521-ba73-a9f664e82c7bf/OU=space:3d2eba6b-ef19-44d5-91dd-1975b0db5cc9/OU=app:2d3e834a-3a25-4591-974c-fa5626d5d0a1" -out instance.csr
openssl x509 -req -in instance.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out instance.crt -days 500 -sha256 -passin pass:test

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
