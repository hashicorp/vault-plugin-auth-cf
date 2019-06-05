package signatures

import (
	"fmt"
	"io/ioutil"
	"testing"
	"time"

	"github.com/hashicorp/vault-plugin-auth-pcf/testing/certificates"
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
		SigningTime: time.Now(),
		Role:        "my-role",
		Certificate: testCerts.InstanceCertificate,
	}

	signature, err := Sign(testCerts.PathToInstanceKey, signatureData)
	if err != nil {
		t.Fatal(err)
	}

	clientCert, err := Verify(signature, signatureData)
	if err != nil {
		t.Fatal(err)
	}

	isIssuer, err := IsIssuer(testCerts.PathToCACertificate, clientCert)
	if err != nil {
		t.Fatal(err)
	}
	if !isIssuer {
		t.Fatal("CA is correct but this says it's not")
	}
}

func TestSignVerifyIssuedByReal(t *testing.T) {
	certBytes, err := ioutil.ReadFile("../testdata/real-certificates/instance.crt")
	if err != nil {
		t.Fatal(err)
	}
	signatureData := &SignatureData{
		SigningTime: time.Now(),
		Role:        "my-role",
		Certificate: string(certBytes),
	}

	signature, err := Sign("../testdata/real-certificates/instance.key", signatureData)
	if err != nil {
		t.Fatal(err)
	}

	clientCert, err := Verify(signature, signatureData)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := IsIssuer("../testdata/real-certificates/ca.crt", clientCert); err == nil {
		t.Fatal(`expected error: x509: certificate has expired or is not yet valid`)
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
		SigningTime: signingTime,
		Role:        sampleRole,
		Certificate: string(certBytes),
	}
	fmt.Println("hashing string: " + signatureData.toSign())
	fmt.Printf("resulting hash: %b\n", signatureData.hash())

	signature, err := Sign(sampleKey, signatureData)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("resulting signature: " + signature)
}
