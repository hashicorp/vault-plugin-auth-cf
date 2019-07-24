package certificates

import (
	"testing"
	"time"

	"github.com/hashicorp/vault-plugin-auth-pcf/models"
	"github.com/hashicorp/vault-plugin-auth-pcf/signatures"
	"github.com/hashicorp/vault-plugin-auth-pcf/util"
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

	pcfCert, err := models.NewPCFCertificateFromx509(signingCert)
	if err != nil {
		t.Fatal(err)
	}
	if pcfCert.InstanceID != "instance-id" {
		t.Fatalf("expected instance-id but received %q", pcfCert.InstanceID)
	}
	if pcfCert.OrgID != "org-id" {
		t.Fatalf("expected org-id but received %q", pcfCert.OrgID)
	}
	if pcfCert.SpaceID != "space-id" {
		t.Fatalf("expected space-id but received %q", pcfCert.SpaceID)
	}
	if pcfCert.AppID != "app-id" {
		t.Fatalf("expected app-id but received %q", pcfCert.AppID)
	}
	if pcfCert.IPAddress != "10.255.181.105" {
		t.Fatalf("expected 10.255.181.105 but received %q", pcfCert.IPAddress)
	}
}
