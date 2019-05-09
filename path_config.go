package pcf

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const configStorageKey = "config"

func (b *backend) pathConfig() *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"certificate": {
				Required:    true,
				Type:        framework.TypeString,
				Description: "The PEM-format CA certificate.",
			},
			"pcf_api_addr": {
				Required:     true,
				Type:         framework.TypeString,
				DisplayName:  "PCF API Address",
				DisplayValue: "https://api.10.244.0.34.xip.io",
				Description:  "PCF’s API address.",
			},
			"pcf_username": {
				Required:     true,
				Type:         framework.TypeString,
				DisplayName:  "PCF API Username",
				DisplayValue: "admin",
				Description:  "The username for PCF’s API.",
			},
			"pcf_password": {
				Required:         true,
				Type:             framework.TypeString,
				DisplayName:      "PCF API Password",
				DisplayValue:     "admin",
				Description:      "The password for PCF’s API.",
				DisplaySensitive: true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.operationConfigCreate,
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.operationConfigRead,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.operationConfigDelete,
			},
		},
		HelpSynopsis:    pathConfigSyn,
		HelpDescription: pathConfigDesc,
	}
}

func (b *backend) operationConfigCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := NewConfiguration(
		data.Get("certificate").(string),
		data.Get("pcf_api_addr").(string),
		data.Get("pcf_username").(string),
		data.Get("pcf_password").(string),
	)
	if err != nil {
		return nil, err
	}
	entry, err := logical.StorageEntryJSON(configStorageKey, config)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	b.configCache.SetDefault(configStorageKey, config)
	return nil, nil
}

func (b *backend) operationConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := b.cachedConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"certificate":  config.Certificate,
			"pcf_api_addr": config.PCFAPIAddr,
			"pcf_username": config.PCFUsername,
		},
	}, nil
}

func (b *backend) operationConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, configStorageKey); err != nil {
		return nil, err
	}
	b.configCache.Delete(configStorageKey)
	return nil, nil
}

func NewConfiguration(certificate, pcfAPIAddr, pcfUsername, pcfPassword string) (*Configuration, error) {
	config := &Configuration{
		Certificate: certificate,
		PCFAPIAddr:  pcfAPIAddr,
		PCFUsername: pcfUsername,
		PCFPassword: pcfPassword,
	}
	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM([]byte(config.Certificate)); !ok {
		return nil, errors.New("couldn't append CA certificates")
	}
	config.verifyOpts = &x509.VerifyOptions{Roots: pool}
	return config, nil
}

type Configuration struct {
	Certificate string `json:"certificate"`
	PCFAPIAddr  string `json:"pcf_api_addr"`
	PCFUsername string `json:"pcf_username"`
	PCFPassword string `json:"pcf_password"`

	// verifyOpts is intentionally lower-cased so it won't be stored in JSON.
	// Instead, this struct is expected to be created from NewConfiguration
	// so that it'll populate this field.
	verifyOpts *x509.VerifyOptions
}

// cachedConfig may return nil without error if the user doesn't currently have a config.
// The cache should always reflect the current stored config, so if the config
// is nil, there's no need to do an additional check in storage.
func (b *backend) cachedConfig(ctx context.Context, storage logical.Storage) (*Configuration, error) {
	configIfc, found := b.configCache.Get(configStorageKey)
	if !found {
		return nil, nil
	}
	config, ok := configIfc.(*Configuration)
	if !ok {
		return nil, fmt.Errorf("couldn't read config: %+v is a %t", configIfc, configIfc)
	}
	return config, nil
}

// storedConfig may return nil without error if the user doesn't currently have a config.
func storedConfig(ctx context.Context, storage logical.Storage) (*Configuration, error) {
	entry, err := storage.Get(ctx, configStorageKey)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	configMap := make(map[string]interface{})
	if err := entry.DecodeJSON(&configMap); err != nil {
		return nil, err
	}
	config, err := NewConfiguration(
		configMap["certificate"].(string),
		configMap["pcf_api_addr"].(string),
		configMap["pcf_username"].(string),
		configMap["pcf_password"].(string),
	)
	if err != nil {
		return nil, err
	}
	return config, nil
}

const pathConfigSyn = `
Provide Vault with the CA certificate used to issue all client certificates.
`

const pathConfigDesc = `
When a login is attempted using a PCF client certificate, Vault will verify
that the client certificate was issued by the CA certificate configured here.
Only those passing this check will be able to gain authorization.
`
