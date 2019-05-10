package pcf

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"reflect"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/parseutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func TestBackend(t *testing.T) {
	ctx := context.Background()
	storage := &logical.InmemStorage{}

	caCertBytes, err := ioutil.ReadFile("testdata/fake/ca.crt")
	if err != nil {
		t.Fatal(err)
	}
	testConf, err := NewConfiguration(
		string(caCertBytes),
		"https://api.10.244.0.34.xip.io",
		"username",
		"password",
	)
	if err != nil {
		t.Fatal(err)
	}

	entry, err := logical.StorageEntryJSON(configStorageKey, testConf)
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.Put(ctx, entry); err != nil {
		t.Fatal(err)
	}

	backend, err := Factory(ctx, &logical.BackendConfig{
		StorageView: storage,
		Logger:      hclog.Default(),
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: time.Hour,
			MaxLeaseTTLVal:     time.Hour,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	parsedCIDRs, err := parseutil.ParseAddrs([]string{"192.168.0.15/24", "192.168.0.15/25"})
	if err != nil {
		t.Fatal(err)
	}

	env := &Env{
		Ctx:      ctx,
		Storage:  storage,
		Backend:  backend,
		TestConf: testConf,
		TestRole: &role{
			BoundAppIDs:      []string{"bound app id 1", "bound app id 2"},
			BoundSpaceIDs:    []string{"bound space id 1", "bound space id 2"},
			BoundOrgIDs:      []string{"bound org id 1", "bound org id 2"},
			BoundInstanceIDs: []string{"bound instance id 1", "bound instance id 2"},
			BoundCIDRs:       parsedCIDRs,
			Policies:         []string{"default", "foo"},
			TTL:              60,
			MaxTTL:           2 * 60,
			Period:           5 * 60,
		},
	}
	t.Run("create config", env.CreateConfig)
	t.Run("read config", env.ReadConfig)
	t.Run("delete config", env.DeleteConfig)
	t.Run("create role", env.CreateRole)
	t.Run("update role", env.UpdateRole)
	t.Run("read role", env.ReadRole)
	t.Run("list roles", env.ListRoles)
	t.Run("delete role", env.DeleteRole)
}

type Env struct {
	Ctx     context.Context
	Storage logical.Storage

	Backend  logical.Backend
	TestConf *configuration
	TestRole *role
}

func (e *Env) CreateConfig(t *testing.T) {
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"certificate":  e.TestConf.Certificate,
			"pcf_api_addr": e.TestConf.PCFAPIAddr,
			"pcf_username": e.TestConf.PCFUsername,
			"pcf_password": e.TestConf.PCFPassword,
		},
	}
	resp, err := e.Backend.HandleRequest(e.Ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr:%v", resp, err)
	}
	if resp != nil {
		t.Fatal("expected nil response to represent a 204")
	}
}

func (e *Env) ReadConfig(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr:%v", resp, err)
	}
	if resp == nil {
		t.Fatal("response shouldn't be nil")
	}
	if resp.Data["certificate"] != e.TestConf.Certificate {
		t.Fatalf("expected %s but received %s", e.TestConf.Certificate, resp.Data["certificate"])
	}
	if resp.Data["pcf_api_addr"] != e.TestConf.PCFAPIAddr {
		t.Fatalf("expected %s but received %s", e.TestConf.PCFAPIAddr, resp.Data["pcf_api_addr"])
	}
	if resp.Data["pcf_username"] != e.TestConf.PCFUsername {
		t.Fatalf("expected %s but received %s", e.TestConf.PCFUsername, resp.Data["pcf_username"])
	}
	if resp.Data["pcf_password"] != nil {
		t.Fatalf("expected %s but received %s", "", resp.Data["pcf_password"])
	}
}

func (e *Env) DeleteConfig(t *testing.T) {
	req := &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "config",
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr:%v", resp, err)
	}
	if resp != nil {
		t.Fatal("expected nil response to represent a 204")
	}
	val, err := e.Storage.Get(e.Ctx, "config")
	if err != nil {
		t.Fatal(err)
	}
	if val != nil {
		t.Fatal("config shouldn't still be in storage")
	}
}

func (e *Env) CreateRole(t *testing.T) {
	cidrs := make([]string, len(e.TestRole.BoundCIDRs))
	for i, cidr := range e.TestRole.BoundCIDRs {
		cidrs[i] = cidr.String()
	}
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/test-role",
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"bound_application_ids":  e.TestRole.BoundAppIDs,
			"bound_space_ids":        e.TestRole.BoundSpaceIDs,
			"bound_organization_ids": e.TestRole.BoundOrgIDs,
			"bound_instance_ids":     e.TestRole.BoundInstanceIDs,
			"bound_cidrs":            cidrs,
			"policies":               e.TestRole.Policies,
			"ttl":                    fmt.Sprintf("%ds", e.TestRole.TTL),
			"max_ttl":                fmt.Sprintf("%ds", e.TestRole.MaxTTL),
			"period":                 fmt.Sprintf("%ds", e.TestRole.Period),
		},
	}
	resp, err := e.Backend.HandleRequest(e.Ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr:%v", resp, err)
	}
	if resp != nil {
		t.Fatal("expected nil response to represent a 204")
	}
	entry, err := e.Storage.Get(e.Ctx, "roles/test-role")
	if err != nil {
		t.Fatal(err)
	}
	r := &role{}
	if err := entry.DecodeJSON(r); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(e.TestRole.BoundAppIDs, r.BoundAppIDs) {
		t.Fatalf("expected %s but received %s", e.TestRole.BoundAppIDs, r.BoundAppIDs)
	}
	if !reflect.DeepEqual(e.TestRole.BoundSpaceIDs, r.BoundSpaceIDs) {
		t.Fatalf("expected %s but received %s", e.TestRole.BoundSpaceIDs, r.BoundSpaceIDs)
	}
	if !reflect.DeepEqual(e.TestRole.BoundOrgIDs, r.BoundOrgIDs) {
		t.Fatalf("expected %s but received %s", e.TestRole.BoundOrgIDs, r.BoundOrgIDs)
	}
	if !reflect.DeepEqual(e.TestRole.BoundInstanceIDs, r.BoundInstanceIDs) {
		t.Fatalf("expected %s but received %s", e.TestRole.BoundInstanceIDs, r.BoundInstanceIDs)
	}
	if !reflect.DeepEqual(e.TestRole.BoundCIDRs, r.BoundCIDRs) {
		t.Fatalf("expected %s but received %s", e.TestRole.BoundCIDRs, r.BoundCIDRs)
	}
	if !reflect.DeepEqual(e.TestRole.Policies, r.Policies) {
		t.Fatalf("expected %s but received %s", e.TestRole.Policies, r.Policies)
	}
	if e.TestRole.TTL*time.Second != r.TTL {
		t.Fatalf("expected %s but received %s", e.TestRole.TTL*time.Second, r.TTL)
	}
	if e.TestRole.MaxTTL*time.Second != r.MaxTTL {
		t.Fatalf("expected %s but received %s", e.TestRole.MaxTTL*time.Second, r.MaxTTL)
	}
	if e.TestRole.Period*time.Second != r.Period {
		t.Fatalf("expected %s but received %s", e.TestRole.Period*time.Second, r.Period)
	}
}

func (e *Env) UpdateRole(t *testing.T) {
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/test-role",
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"bound_space_ids":        []string{},
			"bound_organization_ids": []string{"foo"},
			"bound_instance_ids":     e.TestRole.BoundInstanceIDs,
			"bound_cidrs":            []string{},
			"policies":               e.TestRole.Policies,
			"max_ttl":                "180s",
		},
	}
	resp, err := e.Backend.HandleRequest(e.Ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr:%v", resp, err)
	}
	if resp != nil {
		t.Fatal("expected nil response to represent a 204")
	}
	entry, err := e.Storage.Get(e.Ctx, "roles/test-role")
	if err != nil {
		t.Fatal(err)
	}
	r := &role{}
	if err := entry.DecodeJSON(r); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(e.TestRole.BoundAppIDs, r.BoundAppIDs) {
		t.Fatalf("expected %s but received %s", e.TestRole.BoundAppIDs, r.BoundAppIDs)
	}
	if !reflect.DeepEqual([]string{}, r.BoundSpaceIDs) {
		t.Fatalf("expected %s but received %s", []string{}, r.BoundSpaceIDs)
	}
	if !reflect.DeepEqual([]string{"foo"}, r.BoundOrgIDs) {
		t.Fatalf("expected %s but received %s", []string{"foo"}, r.BoundOrgIDs)
	}
	if !reflect.DeepEqual(e.TestRole.BoundInstanceIDs, r.BoundInstanceIDs) {
		t.Fatalf("expected %s but received %s", e.TestRole.BoundInstanceIDs, r.BoundInstanceIDs)
	}
	if len(r.BoundCIDRs) != 0 {
		t.Fatalf("expected %s but received %s", []string{}, r.BoundCIDRs)
	}
	if !reflect.DeepEqual(e.TestRole.Policies, r.Policies) {
		t.Fatalf("expected %s but received %s", e.TestRole.Policies, r.Policies)
	}
	if e.TestRole.TTL*time.Second != r.TTL {
		t.Fatalf("expected %s but received %s", e.TestRole.TTL*time.Second, r.TTL)
	}
	if time.Duration(180)*time.Second != r.MaxTTL {
		t.Fatalf("expected %s but received %s", e.TestRole.MaxTTL*time.Second, r.MaxTTL)
	}
	if e.TestRole.Period*time.Second != r.Period {
		t.Fatalf("expected %s but received %s", e.TestRole.Period*time.Second, r.Period)
	}
}

func (e *Env) ReadRole(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/test-role",
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr:%v", resp, err)
	}
	if resp == nil {
		t.Fatal("response shouldn't be nil")
	}
	// To reuse the logic above, convert this into a role.
	b, err := json.Marshal(resp.Data)
	if err != nil {
		t.Fatal(err)
	}
	r := &role{}
	if err := json.Unmarshal(b, r); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(e.TestRole.BoundAppIDs, r.BoundAppIDs) {
		t.Fatalf("expected %s but received %s", e.TestRole.BoundAppIDs, r.BoundAppIDs)
	}
	if !reflect.DeepEqual([]string{}, r.BoundSpaceIDs) {
		t.Fatalf("expected %s but received %s", []string{}, r.BoundSpaceIDs)
	}
	if !reflect.DeepEqual([]string{"foo"}, r.BoundOrgIDs) {
		t.Fatalf("expected %s but received %s", []string{"foo"}, r.BoundOrgIDs)
	}
	if !reflect.DeepEqual(e.TestRole.BoundInstanceIDs, r.BoundInstanceIDs) {
		t.Fatalf("expected %s but received %s", e.TestRole.BoundInstanceIDs, r.BoundInstanceIDs)
	}
	if len(r.BoundCIDRs) != 0 {
		t.Fatalf("expected %s but received %s", []string{}, r.BoundCIDRs)
	}
	if !reflect.DeepEqual(e.TestRole.Policies, r.Policies) {
		t.Fatalf("expected %s but received %s", e.TestRole.Policies, r.Policies)
	}
	if time.Duration(60) != r.TTL {
		t.Fatalf("expected %s but received %s", time.Duration(60), r.TTL)
	}
	if time.Duration(180) != r.MaxTTL {
		t.Fatalf("expected %s but received %s", time.Duration(180), r.MaxTTL)
	}
	if time.Duration(300) != r.Period {
		t.Fatalf("expected %s but received %s", time.Duration(300), r.Period)
	}
}

func (e *Env) ListRoles(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ListOperation,
		Path:      "roles",
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr:%v", resp, err)
	}
	if resp == nil {
		t.Fatal("expected nil response to represent a 204")
	}
	if fmt.Sprintf("%s", resp.Data["keys"]) != "[test-role]" {
		t.Fatalf("expected %s but received %s", "[test-role]", resp.Data["keys"])
	}
}

func (e *Env) DeleteRole(t *testing.T) {
	req := &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "roles/test-role",
		Storage:   e.Storage,
	}
	resp, err := e.Backend.HandleRequest(e.Ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr:%v", resp, err)
	}
	if resp != nil {
		t.Fatal("expected nil response to represent a 204")
	}
	val, err := e.Storage.Get(e.Ctx, "roles/test-role")
	if err != nil {
		t.Fatal(err)
	}
	if val != nil {
		t.Fatal("role shouldn't still be in storage")
	}
}
