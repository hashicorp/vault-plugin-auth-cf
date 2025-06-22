// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/hashicorp/vault-plugin-auth-cf/testing/certificates"

	"github.com/hashicorp/vault-plugin-auth-cf/testing/cf"
)

func main() {
	plainServer := cf.MockServer(true, nil, map[string]int{})
	defer plainServer.Close()

	mtlsCerts, err := certificates.GenerateMTLS()
	if err != nil {
		fmt.Printf("could not generate certificates for mTLS: %s", err)
		return
	}
	defer mtlsCerts.Close()

	mtlsServer := cf.MockServer(true, []string{mtlsCerts.SigningCA}, map[string]int{})
	defer mtlsServer.Close()

	fmt.Println("plain server running at " + plainServer.URL)
	fmt.Println("plain server username is " + cf.AuthUsername)
	fmt.Println("plain server password is " + cf.AuthPassword)
	fmt.Println("plain server client id is " + cf.AuthClientID)
	fmt.Println("plain server client secret is " + cf.AuthClientSecret)

	fmt.Println("mtls server is running at " + mtlsServer.URL)
	fmt.Println("mtls server username is " + cf.AuthUsername)
	fmt.Println("mtls server password is " + cf.AuthPassword)
	fmt.Println("mtls server client id is " + cf.AuthClientID)
	fmt.Println("mtls server client secret is " + cf.AuthClientSecret)
	fmt.Println("mtls server CA path is " + mtlsCerts.PathToSigningCA)
	fmt.Println("mtls server will trust certificate at " + mtlsCerts.PathToCertificate)
	fmt.Println("the key for the trusted certificate is at " + mtlsCerts.PathToPrivateKey)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
}
