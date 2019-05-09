package pcf

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/go-sockaddr"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/parseutil"
	"github.com/hashicorp/vault/sdk/logical"
)

const roleStoragePrefix = "roles/"

func (b *backend) pathListRoles() *framework.Path {
	return &framework.Path{
		Pattern: "roles/?$",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.operationRolesList,
			},
		},
		HelpSynopsis:    pathListRolesHelpSyn,
		HelpDescription: pathListRolesHelpDesc,
	}
}

func (b *backend) operationRolesList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, roleStoragePrefix)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(entries), nil
}

func (b *backend) pathRoles() *framework.Path {
	return &framework.Path{
		Pattern: "roles/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Required:    true,
				Description: "The name of the role.",
			},
			"bound_application_ids": {
				Type:         framework.TypeCommaStringSlice,
				DisplayName:  "Bound Application IDs",
				DisplayValue: "6b814521-5f08-4b1a-8c4e-fbe7c5f3a169",
				Description:  "Require that the client certificate presented has at least one of these app IDs.",
			},
			"bound_space_ids": {
				Type:         framework.TypeCommaStringSlice,
				DisplayName:  "Bound Space IDs",
				DisplayValue: "3d2eba6b-ef19-44d5-91dd-1975b0db5cc9",
				Description:  "Require that the client certificate presented has at least one of these space IDs.",
			},
			"bound_organization_ids": {
				Type:         framework.TypeCommaStringSlice,
				DisplayName:  "Bound Organization IDs",
				DisplayValue: "34a878d0-c2f9-4521-ba73-a9f664e82c7b",
				Description:  "Require that the client certificate presented has at least one of these org IDs.",
			},
			"bound_instance_ids": {
				Type:         framework.TypeCommaStringSlice,
				DisplayName:  "Bound Instance IDs",
				DisplayValue: "8a886b31-ccf7-480d-54d8-cc28",
				Description:  "Require that the client certificate presented has at least one of these instance IDs.",
			},
			"bound_cidrs": {
				Type:         framework.TypeCommaStringSlice,
				DisplayName:  "Bound CIDRs",
				DisplayValue: "192.168.100.14/24",
				Description: `Comma separated string or list of CIDR blocks. If set, specifies the blocks of
IP addresses which can perform the login operation.`,
			},
			"policies": {
				Type:         framework.TypeCommaStringSlice,
				Default:      "default",
				DisplayName:  "Policies",
				DisplayValue: "default",
				Description:  "Comma separated list of policies on the role.",
			},
			"ttl": {
				Type: framework.TypeDurationSecond,
				Description: `Duration in seconds after which the issued token should expire. Defaults
to 0, in which case the value will fallback to the system/mount defaults.`,
			},
			"max_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "The maximum allowed lifetime of tokens issued using this role.",
			},
			"period": {
				Type:        framework.TypeDurationSecond,
				Default:     0,
				DisplayName: "Period",
				Description: `If set, indicates that the token generated using this role
should never expire. The token should be renewed within the
duration specified by this value. At each renewal, the token's
TTL will be set to the value of this parameter.`,
			},
		},
		ExistenceCheck: b.operationRolesExistenceCheck,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.operationRolesCreateUpdate,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.operationRolesCreateUpdate,
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.operationRolesRead,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.operationRolesDelete,
			},
		},
		HelpSynopsis:    pathRolesHelpSyn,
		HelpDescription: pathRolesHelpDesc,
	}
}

func (b *backend) operationRolesExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	entry, err := req.Storage.Get(ctx, roleStoragePrefix+data.Get("name").(string))
	if err != nil {
		return false, err
	}
	return entry != nil, nil
}

func (b *backend) operationRolesCreateUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)

	r := &role{}
	if req.Operation == logical.UpdateOperation {
		entry, err := req.Storage.Get(ctx, roleStoragePrefix+roleName)
		if err != nil {
			return nil, err
		}
		if entry != nil {
			if err := entry.DecodeJSON(r); err != nil {
				return nil, err
			}
		}
	}
	if raw, ok := data.GetOk("bound_application_ids"); ok {
		r.BoundAppIDs = raw.([]string)
	}
	if raw, ok := data.GetOk("bound_space_ids"); ok {
		r.BoundSpaceIDs = raw.([]string)
	}
	if raw, ok := data.GetOk("bound_organization_ids"); ok {
		r.BoundOrgIDs = raw.([]string)
	}
	if raw, ok := data.GetOk("bound_instance_ids"); ok {
		r.BoundInstanceIDs = raw.([]string)
	}
	if raw, ok := data.GetOk("bound_cidrs"); ok {
		parsedCIDRs, err := parseutil.ParseAddrs(raw)
		if err != nil {
			return nil, err
		}
		r.BoundCIDRs = parsedCIDRs
	}
	if raw, ok := data.GetOk("policies"); ok {
		r.Policies = raw.([]string)
	}
	if raw, ok := data.GetOk("ttl"); ok {
		r.TTL = time.Duration(raw.(int)) * time.Second
	}
	if raw, ok := data.GetOk("max_ttl"); ok {
		r.MaxTTL = time.Duration(raw.(int)) * time.Second
	}
	if raw, ok := data.GetOk("period"); ok {
		r.Period = time.Duration(raw.(int)) * time.Second
	}

	if r.MaxTTL > 0 && r.TTL > r.MaxTTL {
		return nil, errors.New("ttl exceeds max_ttl")
	}

	entry, err := logical.StorageEntryJSON(roleStoragePrefix+roleName, r)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	if r.TTL > b.System().MaxLeaseTTL() {
		resp := &logical.Response{}
		resp.AddWarning(fmt.Sprintf("ttl of %d exceeds the system max ttl of %d, the latter will be used during login", r.TTL, b.System().MaxLeaseTTL()))
		return resp, nil
	}
	return nil, nil
}

func (b *backend) operationRolesRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)

	r := &role{}
	entry, err := req.Storage.Get(ctx, roleStoragePrefix+roleName)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	if err := entry.DecodeJSON(r); err != nil {
		return nil, err
	}
	cidrs := make([]string, len(r.BoundCIDRs))
	for i, cidr := range r.BoundCIDRs {
		cidrs[i] = cidr.String()
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"bound_application_ids":  r.BoundAppIDs,
			"bound_space_ids":        r.BoundSpaceIDs,
			"bound_organization_ids": r.BoundOrgIDs,
			"bound_instance_ids":     r.BoundInstanceIDs,
			"bound_cidrs":            cidrs,
			"policies":               r.Policies,
			"ttl":                    r.TTL / time.Second,
			"max_ttl":                r.MaxTTL / time.Second,
			"period":                 r.Period / time.Second,
		},
	}, nil
}

func (b *backend) operationRolesDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	if err := req.Storage.Delete(ctx, roleStoragePrefix+roleName); err != nil {
		return nil, err
	}
	return nil, nil
}

type role struct {
	BoundAppIDs      []string                      `json:"bound_application_ids"`
	BoundSpaceIDs    []string                      `json:"bound_space_ids"`
	BoundOrgIDs      []string                      `json:"bound_organization_ids"`
	BoundInstanceIDs []string                      `json:"bound_instance_ids"`
	BoundCIDRs       []*sockaddr.SockAddrMarshaler `json:"bound_cidrs"`
	Policies         []string                      `json:"policies"`
	TTL              time.Duration                 `json:"ttl"`
	MaxTTL           time.Duration                 `json:"max_ttl"`
	Period           time.Duration                 `json:"period"`
}

const pathListRolesHelpSyn = "List the existing roles in this backend."

const pathListRolesHelpDesc = "Roles will be listed by the role name."

// TODO update these...
const pathRolesHelpSyn = `
Read, write and reference policies and roles that API keys or STS credentials can be made for.
`

const pathRolesHelpDesc = `
This path allows you to read and write roles that are used to
create API keys or STS credentials.
If you supply a role ARN, that role must have been created to allow trusted actors,
and the access key and secret that will be used to call AssumeRole (configured at
the /config path) must qualify as a trusted actor.
If you instead supply inline and/or remote policies to be applied, a user and API
key will be dynamically created. The remote policies will be applied to that user,
and the inline policies will also be dynamically created and applied.
To obtain an API key or STS credential after the role is created, if the
backend is mounted at "alicloud" and you create a role at "alicloud/roles/deploy",
then a user could request access credentials at "alicloud/creds/deploy".
To validate the keys, attempt to read an access key after writing the policy.
`
