package main

/*

This tool is for verifying that ca.crt, instance.crt, and instance.key work together.
Usage (example is using the tool from the home directory):

	$ verify-certs -ca-cert=ca.crt -instance-cert=instance.crt -instance-key=instance.key
*/

import (
	"flag"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/hashicorp/vault-plugin-auth-pcf/signatures"
	"github.com/hashicorp/vault-plugin-auth-pcf/util"
)

var (
	// In the cf dev environment, the default CA cert can be found through the found through the following command:
	// $ bosh int --path /diego_instance_identity_ca ~/.cfdev/state/bosh/creds.yml
	// In other environment, the CA certs are managed through Ops Manager.
	pathToCACert = flag.String("ca-cert", "", `The path to the issuing CA certificate: '/path/to/ca.crt'`)

	// In a PCF environment, this will be the value for the environment variable of "CF_INSTANCE_CERT".
	pathToInstanceCert = flag.String("instance-cert", "", `The path to the client certificate: '/path/to/instance.crt'`)

	// In a PCF environment, this will be the value for the environment variable of "CF_INSTANCE_KEY".
	pathToInstanceKey = flag.String("instance-key", "", `The path to the client's private key: '/path/to/instance.key'`)
)

func main() {
	flag.Parse()

	if pathToCACert == nil || *pathToCACert == "" {
		log.Fatal(`"ca-cert" is required`)
	}
	if pathToInstanceCert == nil || *pathToInstanceCert == "" {
		log.Fatal(`"instance-cert" is required`)
	}
	if pathToInstanceKey == nil || *pathToInstanceKey == "" {
		log.Fatal(`"instance-key" is required`)
	}

	dir, err := os.Getwd()
	if err != nil {
		log.Fatalf("couldn't get working directory: %s\n", err)
	}

	caCertBytes, err := ioutil.ReadFile(*pathToCACert)
	if err != nil {
		log.Fatalf("couldn't read %s: %s\n", *pathToCACert, err)
	}

	instanceCertBytes, err := ioutil.ReadFile(*pathToInstanceCert)
	if err != nil {
		log.Fatalf("couldn't read %s: %s\n", *pathToInstanceCert, err)
	}

	signatureData := &signatures.SignatureData{
		SigningTime:            time.Now(),
		CFInstanceCertContents: string(instanceCertBytes),
		Role:                   "test-role",
	}

	// Create a signature.
	signature, err := signatures.Sign(dir+"/"+*pathToInstanceKey, signatureData)
	if err != nil {
		log.Fatalf(`couldn't perform signature: %s\n`, err)
	}

	// Make sure that the signature ties out with the client certificate.
	signingCert, err := signatures.Verify(signature, signatureData)
	if err != nil {
		log.Fatalf(`couldn't verify signature: %s\n`, err)
	}

	intermediateCert, identityCert, err := util.ExtractCertificates(string(instanceCertBytes))
	if err != nil {
		log.Fatalf(`couldn't extract certificates from %s: %s'`, instanceCertBytes, err)
	}

	if err := util.Validate([]string{string(caCertBytes)}, intermediateCert, identityCert, signingCert); err != nil {
		log.Fatalf(`couldn't validate cert chain: %s'`, err)
	}

	log.Print("successfully verified that the given certificates and keys are related to each other")
}
