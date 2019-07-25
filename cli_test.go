package pcf

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/vault-plugin-auth-pcf/models"
	"github.com/hashicorp/vault-plugin-auth-pcf/signatures"
	"github.com/hashicorp/vault-plugin-auth-pcf/testing/certificates"
	"github.com/hashicorp/vault/api"
)

const (
	testInstanceID = "instance-id"
	testOrgID      = "org-id"
	testSpaceID    = "space-id"
	testAppID      = "app-id"
	testIPAddress  = "127.0.0.1"
)

func TestCLIHandler_Auth(t *testing.T) {

	// Make valid fake certificates we can use.
	testCerts, err := certificates.Generate(testInstanceID, testOrgID, testSpaceID, testAppID, testIPAddress)
	if err != nil {
		t.Fatal(err)
	}

	// Make a fake Vault server the client can talk to.
	ts := httptest.NewServer(http.HandlerFunc(handleLogin(t, testCerts)))
	defer ts.Close()

	cliHandler := &CLIHandler{}
	client, err := api.NewClient(&api.Config{
		Address: ts.URL,
	})
	if err != nil {
		t.Fatal(err)
	}

	os.Setenv(EnvVarInstanceCertificate, testCerts.PathToInstanceCertificate)
	os.Setenv(EnvVarInstanceKey, testCerts.PathToInstanceKey)

	if _, err := cliHandler.Auth(client, map[string]string{
		"role": "test-role",
	}); err != nil {
		t.Fatal(err)
	}
}

func handleLogin(t *testing.T, testCerts *certificates.TestCertificates) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		body := make(map[string]string)
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["role"] != "test-role" {
			t.Fatalf(`expected %q but received %q`, "test-role", body["role"])
		}
		if body["cf_instance_cert"] != testCerts.InstanceCertificate {
			t.Fatalf(`expected %q but received %q`, testCerts.InstanceCertificate, body["cf_instance_cert"])
		}
		signingTime, err := time.Parse(signatures.TimeFormat, body["signing_time"])
		if err != nil {
			t.Fatal(err)
		}
		// Perform a loose check that the signing time is reasonable.
		now := time.Now().UTC()
		if now.Sub(signingTime).Minutes() > 2 {
			t.Fatalf(`it's currently %s but signature is from %s'`, now.String(), signingTime.String())
		}

		if body["signature"] == "" {
			t.Fatal("signature is missing")
		}

		signatureData := &signatures.SignatureData{
			SigningTime:            signingTime,
			Role:                   body["role"],
			CFInstanceCertContents: body["cf_instance_cert"],
		}
		// Validate that we can verify the signature that was sent.
		cert, err := signatures.Verify(body["signature"], signatureData)
		if err != nil {
			t.Fatal(err)
		}
		// Validate the certificate that matches our CA has the expected identity data.
		pcfCert, err := models.NewPCFCertificateFromx509(cert)
		if err != nil {
			t.Fatal(err)
		}
		if pcfCert.IPAddress != testIPAddress {
			t.Fatalf(`expected %q but received %q`, testIPAddress, pcfCert.IPAddress)
		}
		if pcfCert.AppID != testAppID {
			t.Fatalf(`expected %q but received %q`, testAppID, pcfCert.AppID)
		}
		if pcfCert.SpaceID != testSpaceID {
			t.Fatalf(`expected %q but received %q`, testSpaceID, pcfCert.SpaceID)
		}
		if pcfCert.OrgID != testOrgID {
			t.Fatalf(`expected %q but received %q`, testOrgID, pcfCert.OrgID)
		}
		if pcfCert.InstanceID != testInstanceID {
			t.Fatalf(`expected %q but received %q`, testInstanceID, pcfCert.InstanceID)
		}
		// Success.
		w.WriteHeader(200)
		w.Write([]byte(successResponse))
	}
}

const successResponse = `{
	"auth": {
		"client_token": "s.JvMmUR9OmjhB7XWtQzSiJBra",
		"accessor": "35rHkAVgFtpNKZvFucAz66iL",
		"policies": [
			"default",
			"dev-policy",
			"my-policy"
		],
		"token_policies": [
			"default",
			"dev-policy",
			"my-policy"
		],
		"metadata": {
			"role_name": "my-role"
		},
		"lease_duration": 2764800,
		"renewable": true,
		"entity_id": "9825b9ac-33c1-b9cc-6424-5657a96df850",
		"token_type": "service"
	}
}`
