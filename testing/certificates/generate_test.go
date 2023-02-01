// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package certificates

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/hashicorp/vault-plugin-auth-cf/models"
	"github.com/hashicorp/vault-plugin-auth-cf/signatures"
	"github.com/hashicorp/vault-plugin-auth-cf/util"
)

func TestGenerate(t *testing.T) {
	testCerts, err := Generate("instance-id", "org-id", "space-id", "app-id", "10.255.181.105")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := testCerts.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	signatureData := &signatures.SignatureData{
		SigningTime:            time.Now(),
		CFInstanceCertContents: testCerts.InstanceCertificate,
		Role:                   "test-role",
	}

	// Create a signature.
	signature, err := signatures.Sign(testCerts.PathToInstanceKey, signatureData)
	if err != nil {
		t.Fatal(err)
	}

	// Make sure that the signature ties out with the client certificate.
	signingCert, err := signatures.Verify(signature, signatureData)
	if err != nil {
		t.Fatal(err)
	}

	intermediateCert, identityCert, err := util.ExtractCertificates(testCerts.InstanceCertificate)
	if err != nil {
		t.Fatal(err)
	}

	// Make sure the signing certificate was issued by the given CA.
	if err := util.Validate([]string{testCerts.CACertificate}, intermediateCert, identityCert, signingCert); err != nil {
		t.Fatal(err)
	}

	cfCert, err := models.NewCFCertificateFromx509(signingCert)
	if err != nil {
		t.Fatal(err)
	}
	if cfCert.InstanceID != "instance-id" {
		t.Fatalf("expected instance-id but received %q", cfCert.InstanceID)
	}
	if cfCert.OrgID != "org-id" {
		t.Fatalf("expected org-id but received %q", cfCert.OrgID)
	}
	if cfCert.SpaceID != "space-id" {
		t.Fatalf("expected space-id but received %q", cfCert.SpaceID)
	}
	if cfCert.AppID != "app-id" {
		t.Fatalf("expected app-id but received %q", cfCert.AppID)
	}
	if cfCert.IPAddress != "10.255.181.105" {
		t.Fatalf("expected 10.255.181.105 but received %q", cfCert.IPAddress)
	}
}

func TestGenerateMTLS(t *testing.T) {
	mtlsCerts, err := GenerateMTLS()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := mtlsCerts.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	certPool := x509.NewCertPool()
	ok := certPool.AppendCertsFromPEM([]byte(mtlsCerts.SigningCA))
	if !ok {
		t.Fatal("could not append CA to cert pool")
	}

	certBlock, _ := pem.Decode([]byte(mtlsCerts.Certificate))
	if certBlock == nil {
		t.Fatalf("could not decode signed certificate")
	}

	signedCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %s", err)
	}

	opts := x509.VerifyOptions{
		Roots:         certPool,
		DNSName:       "vault",
		Intermediates: x509.NewCertPool(),
	}

	if _, err := signedCert.Verify(opts); err != nil {
		t.Fatalf("failed to verify signed certificate: %s", err)
	}
}
