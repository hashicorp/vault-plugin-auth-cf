// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package signatures

import (
	"encoding/base64"
	"io/ioutil"
	"testing"
	"time"

	"github.com/hashicorp/vault-plugin-auth-cf/testing/certificates"
	"github.com/hashicorp/vault-plugin-auth-cf/util"
)

func TestSignVerifyIssuedByFakes(t *testing.T) {
	testCerts, err := certificates.Generate("doesn't", "really", "matter", "here", "10.255.181.105")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := testCerts.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	signatureData := &SignatureData{
		SigningTime:            time.Now(),
		Role:                   "my-role",
		CFInstanceCertContents: testCerts.InstanceCertificate,
	}

	signature, err := Sign(testCerts.PathToInstanceKey, signatureData)
	if err != nil {
		t.Fatal(err)
	}

	signingCert, err := Verify(signature, signatureData)
	if err != nil {
		t.Fatal(err)
	}

	intermediateCert, identityCert, err := util.ExtractCertificates(testCerts.InstanceCertificate)
	if err != nil {
		t.Fatal(err)
	}

	if err := util.Validate([]string{testCerts.CACertificate}, intermediateCert, identityCert, signingCert); err != nil {
		t.Fatal(err)
	}
}

func TestSignVerifyIssuedByReal(t *testing.T) {
	certBytes, err := ioutil.ReadFile("../testdata/real-certificates/instance.crt")
	if err != nil {
		t.Fatal(err)
	}
	signatureData := &SignatureData{
		SigningTime:            time.Now(),
		Role:                   "my-role",
		CFInstanceCertContents: string(certBytes),
	}

	signature, err := Sign("../testdata/real-certificates/instance.key", signatureData)
	if err != nil {
		t.Fatal(err)
	}

	for _, checkURLSafeSig := range []bool{false, true} {
		// Re-encode using old style URL-safe base64 as a compatibility check
		if checkURLSafeSig {
			// strip off "v1:" and decode
			sig, err := base64.StdEncoding.DecodeString(signature[3:])
			if err != nil {
				t.Fatal(err)
			}

			signature = base64.URLEncoding.EncodeToString(sig)
		}

		signingCert, err := Verify(signature, signatureData)
		if err != nil {
			t.Fatal(err)
		}

		caCertBytes, err := ioutil.ReadFile("../testdata/real-certificates/ca.crt")
		if err != nil {
			t.Fatal(err)
		}
		intermediateCert, identityCert, err := util.ExtractCertificates(string(certBytes))
		if err != nil {
			t.Fatal(err)
		}
		if err := util.Validate([]string{string(caCertBytes)}, intermediateCert, identityCert, signingCert); err == nil {
			t.Fatal(`expected error: x509: certificate has expired or is not yet valid`)
		}
	}
}

// TestSignature is present to help implement the signing algorithm in other languages.
func TestSignature(t *testing.T) {
	sampleSigningTime := "2019-05-20T22:08:40Z"
	sampleRole := "sample-role"
	sampleCertificate := "../testdata/real-certificates/instance.crt"
	sampleKey := "../testdata/real-certificates/instance.key"

	signingTime, err := time.Parse(TimeFormat, sampleSigningTime)
	if err != nil {
		t.Fatal(err)
	}
	certBytes, err := ioutil.ReadFile(sampleCertificate)
	if err != nil {
		t.Fatal(err)
	}
	signatureData := &SignatureData{
		SigningTime:            signingTime,
		Role:                   sampleRole,
		CFInstanceCertContents: string(certBytes),
	}
	signature, err := Sign(sampleKey, signatureData)
	if err != nil {
		t.Fatal(err)
	}

	if len(signatureData.hash()) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(signatureData.hash()))
	}

	if len(signature) == 0 {
		t.Errorf("expected non-empty signature")

	}
}
