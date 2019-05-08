package signatures

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
)

var homeDir = func() string {
	wd, _ := os.Getwd()
	return strings.Replace(wd, "/signatures", "", -1)
}()

func TestSignVerifyIssuedByFakes(t *testing.T) {
	body := `{"hello": "world"}`

	loggerOpts := hclog.DefaultOptions
	loggerOpts.Level = hclog.Debug
	logger := hclog.New(loggerOpts)

	signature, signingTime, err := Sign(logger, homeDir+"/fixtures/fake/instance.key", body)
	if err != nil {
		t.Fatal(err)
	}

	clientCert, err := Verify(logger, homeDir+"/fixtures/fake/instance.crt", signature, body, signingTime.Format(TimeFormat))
	if err != nil {
		t.Fatal(err)
	}

	isIssuer, err := IsIssuer(homeDir+"/fixtures/fake/ca.crt", clientCert)
	if err != nil {
		t.Fatal(err)
	}
	if !isIssuer {
		t.Fatal("CA is correct but this says it's not")
	}
}

func TestSignVerifyIssuedByReal(t *testing.T) {
	body := `{"hello": "world"}`

	loggerOpts := hclog.DefaultOptions
	loggerOpts.Level = hclog.Debug
	logger := hclog.New(loggerOpts)

	signature, signingTime, err := Sign(logger, homeDir+"/fixtures/real/instance.key", body)
	if err != nil {
		t.Fatal(err)
	}

	clientCert, err := Verify(logger, homeDir+"/fixtures/real/instance.crt", signature, body, signingTime.Format(TimeFormat))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := IsIssuer(homeDir+"/fixtures/real/ca.crt", clientCert); err == nil {
		t.Fatal(`expected error: x509: certificate has expired or is not yet valid`)
	}
}

func TestGenerateStringToSign(t *testing.T) {
	staticT := time.Date(2017, time.January, 1, 1, 1, 1, 1, time.UTC)
	stringToSign, err := generateStringToSign(hclog.Default(), `{"hello": "world"}`, staticT.Format(TimeFormat))
	if err != nil {
		t.Fatal(err)
	}
	if stringToSign != "time=2017-01-01T01:01:01Z&body=pbxAhSQxn83Jh9R8QJDpYoGllxkDz3SEgzlNpJArvnU=" {
		t.Fatalf(`expected "time=2017-01-01T01:01:01Z&body=pbxAhSQxn83Jh9R8QJDpYoGllxkDz3SEgzlNpJArvnU=" but received %q`, stringToSign)
	}
}
