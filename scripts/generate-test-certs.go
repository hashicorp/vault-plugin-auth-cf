package main

import (
	"fmt"
	"io"
	"log"
	"os"

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
		os.Exit(1)
	}
	wd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
	if err := moveFile(testCerts.PathToCACertificate, wd+"/testdata/fake-certificates/ca.crt"); err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
	if err := moveFile(testCerts.PathToInstanceCertificate, wd+"/testdata/fake-certificates/instance.crt"); err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
	if err := moveFile(testCerts.PathToInstanceKey, wd+"/testdata/fake-certificates/instance.key"); err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
}

func moveFile(sourcePath, destPath string) error {
	inputFile, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer inputFile.Close()
	outputFile, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("unable to create %s: %s", destPath, err)
	}
	defer outputFile.Close()
	if _, err = io.Copy(outputFile, inputFile); err != nil {
		return fmt.Errorf("unable to copy: %s", err)
	}
	if err = os.Remove(sourcePath); err != nil {
		return err
	}
	return nil
}
