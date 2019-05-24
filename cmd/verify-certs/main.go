package main

/*

This tool is for verifying that ca.crt, instance.crt, and instance.key work together.
Usage (example is using the tool from the home directory):

	$ verify-certs -ca-cert=ca.crt -instance-cert=instance.crt -instance-key=instance.key
*/

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"time"

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
)

func main() {
	flag.Parse()

	if pathToCACert == nil || *pathToCACert == "" {
		fmt.Println(`"ca-cert" is required`)
		os.Exit(1)
	}
	if pathToClientCert == nil || *pathToClientCert == "" {
		fmt.Println(`"client-cert" is required`)
		os.Exit(1)
	}
	if pathToClientKey == nil || *pathToClientKey == "" {
		fmt.Println(`"client-key" is required`)
		os.Exit(1)
	}

	dir, err := os.Getwd()
	if err != nil {
		fmt.Printf("couldn't get working directory: %s\n", err)
		os.Exit(1)
	}

	clientCertBytes, err := ioutil.ReadFile(*pathToClientCert)
	if err != nil {
		fmt.Printf("couldn't read %s: %s\n", *pathToClientCert, err)
		os.Exit(1)
	}

	signatureData := &signatures.SignatureData{
		SigningTime: time.Now(),
		Certificate: string(clientCertBytes),
		Role:        "test-role",
	}

	// Create a signature.
	signature, err := signatures.Sign(dir+"/"+*pathToClientKey, signatureData)
	if err != nil {
		fmt.Printf(`couldn't perform signature: %s\n`, err)
		os.Exit(1)
	}

	// Make sure that the signature ties out with the client certificate.
	clientCert, err := signatures.Verify(signature, signatureData)
	if err != nil {
		fmt.Printf(`couldn't verify signature: %s\n`, err)
		os.Exit(1)
	}

	// Make sure the client certificate was issued by the given CA.
	isIssuer, err := signatures.IsIssuer(dir+"/"+*pathToCACert, clientCert)
	if err != nil {
		fmt.Printf(`couldn't confirm issuing CA: %s\n`, err)
		os.Exit(1)
	}
	if !isIssuer {
		fmt.Println("client certificate wasn't issued by this CA")
		os.Exit(1)
	}
	fmt.Println("successfully verified that the given certificates and keys are related to each other")
	os.Exit(0)
}
