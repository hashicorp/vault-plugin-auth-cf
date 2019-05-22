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
		configCache:    cache.New(cache.NoExpiration, -1),
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

	// Populate the configCache from storage.
	config, err := storedConfig(ctx, conf.StorageView)
	if err != nil {
		return nil, err
	}
	if config != nil {
		b.configCache.SetDefault(configStorageKey, config)
	}
	return b, nil
}

type backend struct {
	*framework.Backend
	logger hclog.Logger

	// This cache mirrors storage's state at all times.
	// This cache's lifecycle is:
	//   - On startup, it's populated from storage if it exists.
	//   - On create config calls, it's added or overwritten in the cache.
	//   - On delete config calls, it's removed from the cache.
	// For convenience, use b.cachedConfig() to retrieve its present value.
	configCache *cache.Cache

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
