package main

import (
	"fmt"
	"log"

	"github.com/hashicorp/vault-plugin-auth-pcf/testing/certificates"
)

const (
	orgID      = "34a878d0-c2f9-4521-ba73-a9f664e82c7bf"
	appID      = "2d3e834a-3a25-4591-974c-fa5626d5d0a1"
	spaceID    = "3d2eba6b-ef19-44d5-91dd-1975b0db5cc9"
	instanceID = "1bf2e7f6-2d1d-41ec-501c-c70"
	ipAddr     = "10.255.181.105"
)

func main() {
	testCerts, err := certificates.Generate(instanceID, orgID, spaceID, appID, ipAddr)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("path to CA cert to configure in Vault: %s\n", testCerts.PathToCACertificate)
	fmt.Printf("path to cert to use as CF_INSTANCE_CERT: %s\n", testCerts.PathToInstanceCertificate)
	fmt.Printf("path to key to use as CF_INSTANCE_KEY: %s\n", testCerts.PathToInstanceKey)
}
