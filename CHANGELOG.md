## Unreleased

## 0.21.0
### Jun 03, 2025

IMPROVEMENTS:
* upgrade go to 1.24.3
* Updated dependencies: 
   * github.com/hashicorp/go-secure-stdlib/parseutil v0.1.9 -> v0.2.0
   * github.com/hashicorp/vault/api v1.15.0 -> v1.16.0
   * github.com/hashicorp/vault/sdk v0.14.1 -> v0.17.0
   * golang.org/x/net v0.38.0 -> v0.40.0 
## v0.20.1 (May 12, 2025)

IMPROVEMENTS:

* Bump golang.org/x/net from 0.34.0 to 0.38.0

BUGS:

* Fix a bug where the `cf_timeout` user-provided value was always ignored [GH-104](https://github.com/hashicorp/vault-plugin-auth-cf/pull/104)

## v0.20.0 (February 7, 2025)

IMPROVEMENTS:

* bump go version to 1.23.5
* Updated dependencies:
   * `github.com/hashicorp/go-secure-stdlib/parseutil` v0.1.8 -> v0.1.9
   * `github.com/hashicorp/go-sockaddr` v1.0.6 -> v1.0.7
   * `github.com/hashicorp/vault/api` v1.14.0 -> v1.15.0
   * `github.com/hashicorp/vault/sdk` v0.13.0 -> v0.14.1
   * `github.com/stretchr/testify` v1.9.0 -> v1.10.0
   * `golang.org/x/crypto` v0.31.0 -> v0.32.0
   * `golang.org/x/net` v0.33.0 -> v0.34.0

## v0.19.2 (May 12, 2025)

BUGS:

* Fix a bug where the `cf_timeout` user-provided value was always ignored [GH-104](https://github.com/hashicorp/vault-plugin-auth-cf/pull/104)

## v0.19.1 (January 6, 2025)

IMPROVEMENTS:

* added `cf_timeout` configuration field to customize the CF client timeout [GH-95](https://github.com/hashicorp/vault-plugin-auth-cf/pull/95)
* bump go version to 1.23.3
* updated dependencies
  * bump golang.org/x/crypto to v0.31.0
  * bump golang.org/x/net to v0.33.0

## v0.19.0 (September 4th, 2024)

Dependency Updates:
* `github.com/docker/docker v25.0.5+incompatible` -> v25.0.6+incompatible
* `github.com/hashicorp/vault/api` v1.13.0 -> v1.14.0
* `github.com/hashicorp/vault/sdk` v0.12.0 -> v0.13.0
* `golang.org/x/crypto` v0.23.0 -> v0.26.0
* `golang.org/x/net` v0.25.0 -> v0.28.0

## v0.18.2 (May 12, 2025)

BUGS:

* Fix a bug where the `cf_timeout` user-provided value was always ignored [GH-104](https://github.com/hashicorp/vault-plugin-auth-cf/pull/104)

## v0.18.1 (January 6, 2025)

IMPROVEMENTS:

* added `cf_timeout` configuration field to customize the CF client timeout [GH-96](https://github.com/hashicorp/vault-plugin-auth-cf/pull/96)
* bump go version to 1.23.3

## v0.18.0 (July 8th, 2024)

BUGS:
* Use a single CF client for all requests to avoid connection exhaustion [GH-86](https://github.com/hashicorp/vault-plugin-auth-cf/pull/86) [GH-87](https://github.com/hashicorp/vault-plugin-auth-cf/pull/87)


## v0.17.0 (May 21st, 2023)

* Updated dependencies:
   * `github.com/hashicorp/go-hclog` v1.6.2 -> v1.6.3
   * `github.com/hashicorp/vault/api` v1.11.0 -> v1.13.0
   * `github.com/hashicorp/vault/sdk` v0.10.2 -> v0.12.0
   * `github.com/go-jose/go-jose` v3.0.0 -> v3.0.3
   * `golang.org/x/net` v0.20.0` -> v0.25.0

## v0.16.0 (February 1st, 2023)

IMPROVEMENTS:

* Updated dependencies:
   * `github.com/hashicorp/go-hclog` v1.5.0 -> v1.6.2
   * `github.com/hashicorp/go-secure-stdlib/parseutil` v0.1.7 -> v0.1.8
   * `github.com/hashicorp/go-sockaddr` v1.0.4 -> v1.0.6
   * `github.com/hashicorp/vault/api` v1.9.2 -> v1.11.0
   * `github.com/hashicorp/vault/sdk` v0.9.2 -> v0.10.2
   * `github.com/docker/docker` v24.0.5 -> v25.0.2 (indirect)
   * `golang.org/x/net` v0.14.0 -> v0.20.0
   * `google.golang.org/grpc` v1.53.0 -> v1.61.0 (indirect)

## v0.15.1 (September 5th, 2023)

IMPROVEMENTS:

* Updated dependencies:
   * `github.com/cloudfoundry-community/go-cfclient` v0.0.0-20210823134051-721f0e559306 -> v0.0.0-20220930021109-9c4e6c59ccf1
   * `github.com/hashicorp/go-hclog` v1.0.0 -> v1.5.0
   * `github.com/hashicorp/go-sockaddr` v1.0.2 -> v1.0.4
   * `github.com/hashicorp/go-uuid` v1.0.2 -> v1.0.3
   * `github.com/hashicorp/vault/api` v1.9.1 -> v1.9.2
   * `github.com/hashicorp/vault/sdk` v0.9.0 -> v0.9.2
   * `golang.org/x/net` v0.9.0 -> v0.14.0

## v0.15.0
IMPROVEMENTS

* Add display attributes for OpenAPI OperationID
* enable plugin multiplexing [GH-58](https://github.com/hashicorp/vault-plugin-auth-cf/pull/58)
* update dependencies
  * `github.com/hashicorp/vault/api` v1.9.1
  * `github.com/hashicorp/vault/sdk` v0.9.0
  * `golang.org.x/net` v0.9.0
