package main

/*

This tool is for verifying that ca.crt, instance.crt, and instance.key work together.
Usage (example is using the tool from the home directory):

	$ verify \
		-ca-cert=/fixtures/real/ca.crt \
		-instance-cert=/fixtures/real/instance.crt \
		-instance-key=/fixtures/real/instance.key \
		-debug=true

 */

import (
	"flag"
	"fmt"
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault-plugin-auth-pcf/signatures"
)

var (
	// In the cf dev environment, the default CA cert can be found through the found through the following command:
	// $ bosh int --path /diego_instance_identity_ca ~/.cfdev/state/bosh/creds.yml
	// In other environment, the CA certs are managed through Ops Manager.
	pathToCACert = flag.String("ca-cert", "", `The path to the issuing CA certificate: '/path/to/ca.crt'`)

	// In a PCF environment, this will be the value for the environment variable of "CF_INSTANCE_CERT".
	pathToClientCert = flag.String("instance-cert", "", `The path to the client certificate: '/path/to/instance.crt'`)

	// In a PCF environment, this will be the value for the environment variable of "CF_INSTANCE_KEY".
	pathToClientKey = flag.String("instance-key", "", `The path to the client's private key: '/path/to/instance.key'`)

	debugLevel = flag.Bool("debug", false, `Set to "true" for debug-level logging`)
)

func main(){
	flag.Parse()

	loggerOpts := hclog.DefaultOptions
	if debugLevel != nil && *debugLevel {
		loggerOpts.Level = hclog.Debug
	}
	logger := hclog.New(loggerOpts)

	if pathToCACert == nil || *pathToCACert == "" {
		logger.Error(`"ca-cert" is required`)
		os.Exit(1)
	}
	if pathToClientCert == nil || *pathToClientCert == "" {
		logger.Error(`"client-cert" is required`)
		os.Exit(1)
	}
	if pathToClientKey == nil || *pathToClientKey == "" {
		logger.Error(`"client-key" is required`)
		os.Exit(1)
	}
	logger.Debug("ca cert: " + *pathToCACert)
	logger.Debug("client cert: " + *pathToClientCert)
	logger.Debug("client key: "+ *pathToClientKey)

	dir, err := os.Getwd()
	if err != nil {
		logger.Error("couldn't get working directory: " + err.Error())
	}

	// Make up a test body since we're only checking that the
	// certificates work together here.
	bodyJson := `{"hello": "world"}`

	// Sign something
	signature, signingTime, err := signatures.Sign(logger, dir+*pathToClientKey, bodyJson)
	if err != nil {
		logger.Error(fmt.Sprintf(`couldn't perform signature: %s'`, err))
		os.Exit(1)
	}

	// Make sure that the signature ties out with the client certificate.
	if err := signatures.Verify(logger, dir+*pathToClientCert, signature, bodyJson, signingTime.Format(signatures.TimeFormat)); err != nil {
		logger.Error(fmt.Sprintf(`couldn't verify signature: %s'`, err))
		os.Exit(1)
	}

	// Make sure the client certificate was issued by the given CA.
	isIssuer, err := signatures.IsIssuer(dir+*pathToCACert, dir+*pathToClientCert)
	if err != nil {
		logger.Error(fmt.Sprintf(`couldn't confirm issuing CA: %s'`, err))
		os.Exit(1)
	}
	if !isIssuer {
		logger.Error("client certificate wasn't issued by this CA")
		os.Exit(1)
	}
	logger.Info("successfully verified that the given certificates and keys are related to each other")
	os.Exit(0)
}
