// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package util

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"

	"github.com/cloudfoundry-community/go-cfclient"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/vault-plugin-auth-cf/models"
)

const BashTimeFormat = "Mon Jan 2 15:04:05 MST 2006"

// NewCFClient does some work that's needed every time we use the CF client,
// namely using cleanhttp and configuring it to match the user conf.
func NewCFClient(config *models.Configuration) (*cfclient.Client, error) {
	clientConf := &cfclient.Config{
		ApiAddress:   config.CFAPIAddr,
		Username:     config.CFUsername,
		Password:     config.CFPassword,
		ClientID:     config.CFClientID,
		ClientSecret: config.CFClientSecret,
		HttpClient:   cleanhttp.DefaultClient(),
	}
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	for _, certificate := range config.CFAPICertificates {
		if ok := rootCAs.AppendCertsFromPEM([]byte(certificate)); !ok {
			return nil, fmt.Errorf("couldn't append CF API cert to trust: %s", certificate)
		}
	}
	tlsConfig := &tls.Config{
		RootCAs: rootCAs,
	}

	if config.CFMutualTLSCertificate != "" && config.CFMutualTLSKey != "" {
		cert, err := tls.X509KeyPair(
			[]byte(config.CFMutualTLSCertificate),
			[]byte(config.CFMutualTLSKey),
		)

		if err != nil {
			return nil, fmt.Errorf("could not parse X509 key pair for mutual TLS")
		}

		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	clientConf.HttpClient.Transport = &http.Transport{TLSClientConfig: tlsConfig}
	return cfclient.NewClient(clientConf)
}
