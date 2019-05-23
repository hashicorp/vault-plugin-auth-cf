package pcf

import (
	"context"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/patrickmn/go-cache"
)

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &backend{
		logger:         hclog.Default(),
		signatureCache: cache.New(time.Minute*5, time.Second*30),
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

	// The signature cache guards against replay attacks by hanging onto
	// all the signatures it's seen in the last 5 minutes. Logins aren't
	// allowed using the same signature twice, which should be fine because
	// signatures include randomness. Logins using signatures over 5 minutes
	// old aren't allowed, so that takes over for replay attack prevention
	// afterwards.
	signatureCache *cache.Cache
}

const backendHelp = `
The PCF auth backend supports logging in using PCF's identity service.
Once a CA certificate is configured, and Vault is configured to consume
PCF's API, PCF's instance identity credentials can be used to authenticate.'
`
