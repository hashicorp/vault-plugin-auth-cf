package pcf

import (
	"context"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &backend{
		logger: hclog.Default(),
	}
	b.Backend = &framework.Backend{
		AuthRenew: b.pathLoginRenew,
		Help:      backendHelp,
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{"config"},
			Unauthenticated: []string{"login"},
		},
		Paths: []*framework.Path{
			b.pathConfig(),
			b.pathListRoles(),
			b.pathRoles(),
			b.pathLogin(),
		},
		BackendType: logical.TypeCredential,
	}
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

type backend struct {
	*framework.Backend
	logger hclog.Logger
}

const backendHelp = `
The PCF auth backend supports logging in using PCF's identity service.
Once a CA certificate is configured, and Vault is configured to consume
PCF's API, PCF's instance identity credentials can be used to authenticate.'
`
