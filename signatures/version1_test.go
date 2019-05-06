package signatures

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
)

var homeDir = func () string {
	wd, _ := os.Getwd()
	return strings.Replace(wd, "/signatures", "", -1)
}()

func TestSignVerify(t *testing.T) {
	body := `{"hello": "world"}`

	loggerOpts := hclog.DefaultOptions
	loggerOpts.Level = hclog.Debug
	logger := hclog.New(loggerOpts)

	signature, signingTime, err := Sign(logger, homeDir + "/fixtures/fake/instance.key", body)
	if err != nil {
		t.Fatal(err)
	}

	if err := Verify(logger, homeDir + "/fixtures/fake/instance.crt", signature, body, signingTime.Format(TimeFormat)); err != nil {
		t.Fatal(err)
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

func TestIsIssuer(t *testing.T) {
	is, err := IsIssuer(homeDir + "/fixtures/real/ca.crt", homeDir + "/fixtures/real/instance.crt")
	if err != nil {
		t.Fatal(err)
	}
	if !is {
		t.Fatal("CA is correct but this says it's not")
	}
}