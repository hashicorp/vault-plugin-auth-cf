package pcf

import (
	"context"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	cache "github.com/patrickmn/go-cache"
)

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &backend{
		configCache: cache.New(cache.NoExpiration, -1),
	}
	b.Backend = &framework.Backend{
		Help: backendHelp,
		Paths: []*framework.Path{
			b.pathConfig(),
		},
		BackendType: logical.TypeCredential,
	}

	// Populate the configCache from storage.
	config, err := StoredConfig(ctx, conf.StorageView)
	if err != nil {
		return nil, err
	}
	if config != nil {
		b.configCache.SetDefault(configStorageKey, &config)
	}
	return b, nil
}

type backend struct {
	*framework.Backend

	// This cache mirrors storage's state at all times.
	// This cache's lifecycle is:
	//   - On startup, it's populated from storage if it exists.
	//   - On create config calls, it's added or overwritten in the cache.
	//   - On delete config calls, it's removed from the cache.
	// Use CachedConfig() to retrieve the present value.
	configCache *cache.Cache
}

const backendHelp = `
The PCF auth backend supports logging in using PCF's identity service.
Once a CA certificate is configured, and Vault is configured to consume
PCF's API, PCF's instance identity credentials can be used to authenticate.'
`
