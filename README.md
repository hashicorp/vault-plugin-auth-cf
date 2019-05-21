# vault-plugin-auth-pcf

## Getting Started

- `$ git clone git@github.com:hashicorp/vault-plugin-auth-pcf.git`
- `$ cd vault-plugin-auth-pcf`
- `$ make test`
- `$ make tools`

`$ make test` is run above to generate valid fake certificates in your `testdata/fake-certificates` folder.
`$ make tools` is run above to install a number of tools that have been placed here in the `cmd` directory 
to make your life easier. Running the command will place them in your `$GOPATH/bin` directory.

## Sample Usage

Please note that this example uses `generate-signature`, a tool installed through `$ make tools`.

```
$ vault auth enable vault-plugin-auth-pcf

$ vault write auth/vault-plugin-auth-pcf/config \
    certificate=@$GOPATH/src/github.com/hashicorp/vault-plugin-auth-pcf/testdata/fake-certificates/ca.crt \
    pcf_api_addr=http://127.0.0.1:33671 \
    pcf_username=username \
    pcf_password=password
    
$ vault write auth/vault-plugin-auth-pcf/roles/test-role \
    bound_application_ids=2d3e834a-3a25-4591-974c-fa5626d5d0a1 \
    bound_space_ids=3d2eba6b-ef19-44d5-91dd-1975b0db5cc9 \
    bound_organization_ids=34a878d0-c2f9-4521-ba73-a9f664e82c7bf \
    bound_instance_ids=1bf2e7f6-2d1d-41ec-501c-c70 \
    policies=foo-policies \
    disable_ip_matching=true \
    ttl=86400s \
    max_ttl=86400s \
    period=86400s
    
$ export CF_INSTANCE_CERT=$GOPATH/src/github.com/hashicorp/vault-plugin-auth-pcf/testdata/fake-certificates/instance.crt
$ export CF_INSTANCE_KEY=$GOPATH/src/github.com/hashicorp/vault-plugin-auth-pcf/testdata/fake-certificates/instance.key
$ export SIGNING_TIME=$(date -u)
$ export ROLE='test-role'
$ vault write auth/vault-plugin-auth-pcf/login \
    role=$ROLE \
    certificate=@$CF_INSTANCE_CERT \
    signing-time="$SIGNING_TIME" \
    signature=$(generate-signature)
```

## Troubleshooting

### verify-certs

This tool, installed by `make tools`, is for verifying that your CA certificate, client certificate, and client 
key are all properly related to each other and will pass verification if used by this auth engine. If you're 
debugging authentication problems that may be related to your certificates, it's a fantastic tool to use.

```
verify-certs -ca-cert=local/path/to/ca.crt -instance-cert=local/path/to/instance.crt -instance-key=local/path/to/instance.key
```
The `ca-cert` should be the cert that was used to issue the given client certificate. In the CF Dev environment,
it can be obtained via `$ bosh int --path /diego_instance_identity_ca ~/.cfdev/state/bosh/creds.yml`. In a prod
environment, it should be available through the Ops Manager API.

The `instance-cert` given should be the value for the `CF_INSTANCE_CERT` variable in the PCF environment you're
using, and the `instance-key` should be the value for the `CF_INSTANCE_KEY`.

The tool does take the _local path to_ these certificates, so you'll need to gather them and place them on your
local machine to verify they all will work together.

### generate-signature

This tool, installed by `make tools`, is for generating a valid signature to be used for signing into Vault via PCF. 

It can be used as a standalone tool for generating a signature like so:
```
export CF_INSTANCE_CERT=path/to/instance.crt
export CF_INSTANCE_KEY=path/to/instance.key
export SIGNING_TIME=$(date -u)
export ROLE='test-role'
generate-signature
```

It can also be used for signing into Vault like so:
```
export CF_INSTANCE_CERT=path/to/instance.crt
export CF_INSTANCE_KEY=path/to/instance.key
export SIGNING_TIME=$(date -u)
export ROLE='test-role'

vault write auth/vault-plugin-auth-pcf/login \
    role=$ROLE \
    certificate=$CF_INSTANCE_CERT \
    signing-time=SIGNING_TIME \
    signature=$(generate-signature)
```
If the tool is being run in a PCF environment already containing the `CF_INSTANCE_CERT` and `CF_INSTANCE_KEY`, those
variables obviously won't need to be manually set before the tool is used and can just be pulled as they are.

## Developing

### mock-pcf-server

This tool, installed by `make tools`, is for use in development. It lets you run a mocked PCF server for use in local 
testing, with output that can be used as the `pcf_api_addr`, `pcf_username`, and `pcf_password` in your config.

Example use:
```
$ mock-pcf-server
running at http://127.0.0.1:33671
username is username
password is password
```

Simply hit CTRL+C to stop the test server.

### Implementing the Signature Algorithm in Other Languages

The signing algorithm used by this plugin is viewable in `signatures/version1.go`. There is also a test
called `TestSignature` in the same package that outputs a viewable signing string, hash of it, and
resulting signature. The signature will be different every time the test is run because some
of the input to the final signature includes cryptographically random material. This means that no matter
what you do, your final signature won't match any signatures shown; the important thing, however, is that 
it can be verified as having been signed by the private key that's associated with the given client
certificate.

To develop your own version of the signing algorithm in a different language, we recommend you duplicate
the inputs to `TestSignature`, duplicate its signing string and hash, and duplicate the signing algorithm used.

### Quick Start

```
# After cloning the repo, generate fake certs, a test binary, and install the tools.
make test
make dev
make tools

# In one shell window, run Vault with the plugin available in the catalog.
vault server -dev -dev-root-token-id=root -dev-plugin-dir=$GOPATH/src/github.com/hashicorp/vault-plugin-auth-pcf/bin -log-level=debug

# In another shell window, run a mock of the PCF API so the plugin's client calls won't fail.
mock-pcf-server

# In another shell window, execute the following commands to exercise each endpoint.
export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=root
export MOCK_PCF_SERVER_ADDR='something' # ex. http://127.0.0.1:32937

vault auth enable vault-plugin-auth-pcf

vault write auth/vault-plugin-auth-pcf/config \
    certificate=@$GOPATH/src/github.com/hashicorp/vault-plugin-auth-pcf/testdata/fake-certificates/ca.crt \
    pcf_api_addr=$MOCK_PCF_SERVER_ADDR \
    pcf_username=username \
    pcf_password=password
    
vault write auth/vault-plugin-auth-pcf/roles/test-role \
    bound_application_ids=2d3e834a-3a25-4591-974c-fa5626d5d0a1 \
    bound_space_ids=3d2eba6b-ef19-44d5-91dd-1975b0db5cc9 \
    bound_organization_ids=34a878d0-c2f9-4521-ba73-a9f664e82c7bf \
    bound_instance_ids=1bf2e7f6-2d1d-41ec-501c-c70 \
    policies=foo,policies \
    disable_ip_matching=true \
    ttl=86400s \
    max_ttl=86400s \
    period=86400s
    
export CF_INSTANCE_CERT=$GOPATH/src/github.com/hashicorp/vault-plugin-auth-pcf/testdata/fake-certificates/instance.crt
export CF_INSTANCE_KEY=$GOPATH/src/github.com/hashicorp/vault-plugin-auth-pcf/testdata/fake-certificates/instance.key
export SIGNING_TIME=$(date -u)
export ROLE='test-role'
vault write auth/vault-plugin-auth-pcf/login \
    role=$ROLE \
    certificate=@$CF_INSTANCE_CERT \
    signing-time="$SIGNING_TIME" \
    signature=$(generate-signature)
```