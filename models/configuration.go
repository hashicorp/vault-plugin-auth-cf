package models

import (
	"crypto/x509"
	"fmt"
)

func NewConfiguration(certificates []string, pcfAPIAddr, pcfUsername, pcfPassword string) (*Configuration, error) {
	config := &Configuration{
		Certificates: certificates,
		PCFAPIAddr:   pcfAPIAddr,
		PCFUsername:  pcfUsername,
		PCFPassword:  pcfPassword,
	}
	pool := x509.NewCertPool()
	for _, certificate := range certificates {
		if ok := pool.AppendCertsFromPEM([]byte(certificate)); !ok {
			return nil, fmt.Errorf("couldn't append CA certificate: %s", certificate)
		}
	}
	config.verifyOpts = &x509.VerifyOptions{Roots: pool}
	return config, nil
}

type Configuration struct {
	Certificates []string `json:"certificates"`
	PCFAPIAddr   string   `json:"pcf_api_addr"`
	PCFUsername  string   `json:"pcf_username"`
	PCFPassword  string   `json:"pcf_password"`

	// verifyOpts is intentionally lower-cased so it won't be stored in JSON.
	// Instead, this struct is expected to be created from NewConfiguration
	// so that it'll populate this field.
	verifyOpts *x509.VerifyOptions
}

func (c *Configuration) VerifyOpts() x509.VerifyOptions {
	return *c.verifyOpts
}
