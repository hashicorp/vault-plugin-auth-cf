package main

/*

Usage:

	export CF_INSTANCE_CERT=path/to/instance.crt
	export CF_INSTANCE_KEY=path/to/instance.key
	export SIGNING_TIME=$(date -u)
	export ROLE='test-role'
	generate-signature

To use it for directly logging into Vault:

	export CF_INSTANCE_CERT=path/to/instance.crt
	export CF_INSTANCE_KEY=path/to/instance.key
	export SIGNING_TIME=$(date -u)
	export ROLE='test-role'
	vault write auth/vault-plugin-auth-pcf/login \
		role=$ROLE \
		certificate=$CF_INSTANCE_CERT \
		signing_time=SIGNING_TIME \
		signature=$(generate-signature)
*/

import (
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/hashicorp/vault-plugin-auth-pcf/signatures"
	"github.com/hashicorp/vault-plugin-auth-pcf/util"
)

func main() {
	signingTimeRaw := os.Getenv("SIGNING_TIME")
	signingTime, err := time.Parse(util.BashTimeFormat, signingTimeRaw)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	pathToClientCert := os.Getenv("CF_INSTANCE_CERT")
	pathToClientKey := os.Getenv("CF_INSTANCE_KEY")
	roleName := os.Getenv("ROLE")

	clientCertBytes, err := ioutil.ReadFile(pathToClientCert)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	signature, err := signatures.Sign(pathToClientKey, &signatures.SignatureData{
		SigningTime: signingTime,
		Certificate: string(clientCertBytes),
		Role:        roleName,
	})
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(signature)
	os.Exit(0)
}
