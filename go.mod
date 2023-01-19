module github.com/hashicorp/vault-plugin-auth-cf

go 1.12

require (
	github.com/cloudfoundry-community/go-cfclient v0.0.0-20210823134051-721f0e559306
	github.com/hashicorp/go-cleanhttp v0.5.2
	github.com/hashicorp/go-hclog v1.0.0
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hashicorp/go-secure-stdlib/parseutil v0.1.6
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2
	github.com/hashicorp/go-sockaddr v1.0.2
	github.com/hashicorp/go-uuid v1.0.2
	github.com/hashicorp/vault/api v1.2.0
	github.com/hashicorp/vault/sdk v0.5.3
	github.com/hashicorp/yamux v0.0.0-20181012175058-2f1d1f20f75d // indirect
	github.com/pkg/errors v0.9.1
	golang.org/x/net v0.0.0-20210226172049-e18ecbb05110
	golang.org/x/sys v0.0.0-20220422013727-9388b58f7150 // indirect
)
