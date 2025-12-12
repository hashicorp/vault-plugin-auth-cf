// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cf

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cloudfoundry-community/go-cfclient"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hashicorp/vault-plugin-auth-cf/models"
	"github.com/hashicorp/vault-plugin-auth-cf/signatures"
	"github.com/hashicorp/vault-plugin-auth-cf/testing/certificates"
	"github.com/hashicorp/vault-plugin-auth-cf/testing/cf"
)

func TestBackend(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	storage := &logical.InmemStorage{}

	testCerts, err := certificates.Generate(cf.FoundServiceGUID, cf.FoundOrgGUID, cf.FoundSpaceGUID, cf.FoundAppGUID, "10.255.181.105")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := testCerts.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	invalidCaCertBytes, err := ioutil.ReadFile("testdata/real-certificates/ca.crt")
	if err != nil {
		t.Fatal(err)
	}

	cfServer := cf.MockServer(false, nil, map[string]int{})
	defer cfServer.Close()

	testConf := &models.Configuration{
		IdentityCACertificates: []string{testCerts.CACertificate, string(invalidCaCertBytes)},
		CFAPIAddr:              cfServer.URL,
		CFUsername:             cf.AuthUsername,
		CFPassword:             cf.AuthPassword,
		CFClientID:             cf.AuthClientID,
		CFClientSecret:         cf.AuthClientSecret,
		CFTimeout:              30 * time.Second,
		LoginMaxSecNotBefore:   5,
		LoginMaxSecNotAfter:    1,
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
	parsedCIDRs, err := parseutil.ParseAddrs([]string{"10.255.181.105/24"})
	if err != nil {
		t.Fatal(err)
	}

	env := &Env{
		Ctx:      ctx,
		Storage:  storage,
		Backend:  backend,
		TestConf: testConf,
		TestRole: &models.RoleEntry{
			BoundAppIDs:      []string{cf.FoundAppGUID},
			BoundSpaceIDs:    []string{cf.FoundSpaceGUID},
			BoundOrgIDs:      []string{cf.FoundOrgGUID},
			BoundInstanceIDs: []string{cf.FoundServiceGUID},
			BoundCIDRs:       parsedCIDRs,
			Policies:         []string{"default", "foo"},
			TTL:              60,
			MaxTTL:           2 * 60,
			Period:           5 * 60,
		},
		TestCerts: testCerts,
	}
	// Exercise all the endpoints.
	t.Run("create old config", env.StoreV0Config)
	t.Run("read old config", env.ReadV0Config)
	t.Run("create config", env.CreateConfig)
	t.Run("read config", env.ReadConfig)
	t.Run("update config", env.UpdateConfig)
	t.Run("read updated config", env.ReadUpdatedConfig)
	t.Run("delete config", env.DeleteConfig)
	t.Run("create role", env.CreateRole)
	t.Run("update role", env.UpdateRole)
	t.Run("read role", env.ReadRole)
	t.Run("list roles", env.ListRoles)
	t.Run("delete role", env.DeleteRole)

	// Actually perform the flow needed to log in.
	t.Run("create config", env.CreateConfig)
	t.Run("create role", env.CreateRole)
	t.Run("login", env.Login)
}

// TestBackend_Client tests the backend's CF client after certain events
func TestBackend_Client(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	storage := &logical.InmemStorage{}

	testCerts, err := certificates.Generate(cf.FoundServiceGUID, cf.FoundOrgGUID, cf.FoundSpaceGUID, cf.FoundAppGUID, "10.255.181.105")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := testCerts.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	cfServer := cf.MockServer(false, nil, map[string]int{})
	defer cfServer.Close()

	testConf := &models.Configuration{
		IdentityCACertificates: []string{testCerts.CACertificate},
		CFAPIAddr:              cfServer.URL,
		CFUsername:             cf.AuthUsername,
		CFPassword:             cf.AuthPassword,
		CFClientID:             cf.AuthClientID,
		CFClientSecret:         cf.AuthClientSecret,
		CFTimeout:              30 * time.Second,
	}

	be, err := Factory(ctx, &logical.BackendConfig{
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
	parsedCIDRs, err := parseutil.ParseAddrs([]string{"10.255.181.105/24"})
	if err != nil {
		t.Fatal(err)
	}

	env := &Env{
		Ctx:      ctx,
		Storage:  storage,
		Backend:  be,
		TestConf: testConf,
		TestRole: &models.RoleEntry{
			BoundAppIDs:      []string{cf.FoundAppGUID},
			BoundSpaceIDs:    []string{cf.FoundSpaceGUID},
			BoundOrgIDs:      []string{cf.FoundOrgGUID},
			BoundInstanceIDs: []string{cf.FoundServiceGUID},
			BoundCIDRs:       parsedCIDRs,
			Policies:         []string{"default", "foo"},
			TTL:              60,
			MaxTTL:           2 * 60,
			Period:           5 * 60,
		},
		TestCerts: testCerts,
	}

	// Check CF client after events like initialization and config writes
	bEnd := env.Backend.(*backend)
	originalClient := bEnd.cfClient
	originalConfigHash := bEnd.lastConfigHash
	require.Nil(t, originalClient, "expected the CF client to be nil")
	require.Nil(t, originalConfigHash, "expected the config hash to be nil")

	t.Run("create config", env.CreateConfig)
	require.NotEqual(t, originalClient, bEnd.cfClient, "expected the CF client to be initialized")
	require.NotEqual(t, originalConfigHash, bEnd.lastConfigHash, "expected the config hash to be initialized")

	// Update config slightly
	originalClient = bEnd.cfClient
	originalConfigHash = bEnd.lastConfigHash
	env.TestConf.CFTimeout = 60 * time.Second
	t.Run("update config", env.CreateConfig)
	require.NotEqual(t, originalClient, bEnd.cfClient, "expected the CF client to be updated")
	require.NotEqual(t, originalConfigHash, bEnd.lastConfigHash, "expected the config hash to be updated")

	// Update config with the same values, make sure client doesn't change
	originalClient = bEnd.cfClient
	originalConfigHash = bEnd.lastConfigHash
	t.Run("update config with same values", env.CreateConfig)
	require.Equal(t, originalClient, bEnd.cfClient, "expected the CF client to be the same")
	require.Equal(t, originalConfigHash, bEnd.lastConfigHash, "expected the config hash to be the same")
}

// TestBackend_Login tests CF client behavior after an API request fails
// It should reinitialize the CF client, retry and then succeed
func TestBackend_Login(t *testing.T) {
	ctx := context.Background()
	storage := &logical.InmemStorage{}

	testCerts, err := certificates.Generate(cf.FoundServiceGUID, cf.FoundOrgGUID, cf.FoundSpaceGUID, cf.FoundAppGUID, "10.255.181.105")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := testCerts.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	invalidCaCertBytes, err := ioutil.ReadFile("testdata/real-certificates/ca.crt")
	if err != nil {
		t.Fatal(err)
	}

	cfServer := cf.MockServer(false, nil, map[string]int{cf.FoundAppGUID: 1})
	defer cfServer.Close()

	testConf := &models.Configuration{
		IdentityCACertificates: []string{testCerts.CACertificate, string(invalidCaCertBytes)},
		CFAPIAddr:              cfServer.URL,
		CFUsername:             cf.AuthUsername,
		CFPassword:             cf.AuthPassword,
		CFClientID:             cf.AuthClientID,
		CFClientSecret:         cf.AuthClientSecret,
		CFTimeout:              30 * time.Second,
		LoginMaxSecNotBefore:   5,
		LoginMaxSecNotAfter:    1,
	}

	be, err := Factory(ctx, &logical.BackendConfig{
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
	parsedCIDRs, err := parseutil.ParseAddrs([]string{"10.255.181.105/24"})
	if err != nil {
		t.Fatal(err)
	}

	env := &Env{
		Ctx:      ctx,
		Storage:  storage,
		Backend:  be,
		TestConf: testConf,
		TestRole: &models.RoleEntry{
			BoundAppIDs:      []string{cf.FoundAppGUID},
			BoundSpaceIDs:    []string{cf.FoundSpaceGUID},
			BoundOrgIDs:      []string{cf.FoundOrgGUID},
			BoundInstanceIDs: []string{cf.FoundServiceGUID},
			BoundCIDRs:       parsedCIDRs,
			Policies:         []string{"default", "foo"},
			TTL:              60,
			MaxTTL:           2 * 60,
			Period:           5 * 60,
		},
		TestCerts: testCerts,
	}
	bEnd := env.Backend.(*backend)

	t.Run("create config", env.CreateConfig)
	originalClient := bEnd.cfClient
	t.Run("create role", env.CreateRole)
	require.Equal(t, originalClient, bEnd.cfClient, "expected the CF client to be the same after creating the role")
	t.Run("login", env.Login)
	require.NotEqual(t, originalClient, bEnd.cfClient, "expected the CF client to refresh after first login attempt failed")

	originalClient = bEnd.cfClient
	t.Run("login", env.Login)
	require.Equal(t, originalClient, bEnd.cfClient, "expected the CF client to be the same after first login attempt succeeded")
}

func TestBackendMTLS(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	storage := &logical.InmemStorage{}

	testCerts, err := certificates.Generate(cf.FoundServiceGUID, cf.FoundOrgGUID, cf.FoundSpaceGUID, cf.FoundAppGUID, "10.255.181.105")
	if err != nil {
		t.Fatal(err)
	}

	mtlsTestCerts, err := certificates.GenerateMTLS()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := testCerts.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	invalidCaCertBytes, err := ioutil.ReadFile("testdata/real-certificates/ca.crt")
	if err != nil {
		t.Fatal(err)
	}

	cfServer := cf.MockServer(false, []string{mtlsTestCerts.SigningCA}, map[string]int{})
	defer cfServer.Close()

	testConf := &models.Configuration{
		IdentityCACertificates: []string{testCerts.CACertificate, string(invalidCaCertBytes)},
		CFMutualTLSCertificate: mtlsTestCerts.Certificate,
		CFMutualTLSKey:         mtlsTestCerts.PrivateKey,
		CFAPIAddr:              cfServer.URL,
		CFUsername:             cf.AuthUsername,
		CFPassword:             cf.AuthPassword,
		LoginMaxSecNotBefore:   5,
		LoginMaxSecNotAfter:    1,
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
	parsedCIDRs, err := parseutil.ParseAddrs([]string{"10.255.181.105/24"})
	if err != nil {
		t.Fatal(err)
	}

	env := &Env{
		Ctx:      ctx,
		Storage:  storage,
		Backend:  backend,
		TestConf: testConf,
		TestRole: &models.RoleEntry{
			BoundAppIDs:      []string{cf.FoundAppGUID},
			BoundSpaceIDs:    []string{cf.FoundSpaceGUID},
			BoundOrgIDs:      []string{cf.FoundOrgGUID},
			BoundInstanceIDs: []string{cf.FoundServiceGUID},
			BoundCIDRs:       parsedCIDRs,
			Policies:         []string{"default", "foo"},
			TTL:              60,
			MaxTTL:           2 * 60,
			Period:           5 * 60,
		},
		TestCerts: testCerts,
	}
	// Exercise all the endpoints.
	t.Run("create old config", env.StoreV0Config)
	t.Run("read old config", env.ReadV0Config)
	t.Run("create config", env.CreateConfig)
	t.Run("read config", env.ReadConfig)
	t.Run("update config", env.UpdateConfig)
	t.Run("read updated config", env.ReadUpdatedConfig)
	t.Run("delete config", env.DeleteConfig)
	t.Run("create role", env.CreateRole)
	t.Run("update role", env.UpdateRole)
	t.Run("read role", env.ReadRole)
	t.Run("list roles", env.ListRoles)
	t.Run("delete role", env.DeleteRole)

	// Actually perform the flow needed to log in.
	t.Run("create config", env.CreateConfig)
	t.Run("create role", env.CreateRole)
	t.Run("login", env.Login)
}

type Env struct {
	Ctx     context.Context
	Storage logical.Storage

	Backend   logical.Backend
	TestConf  *models.Configuration
	TestRole  *models.RoleEntry
	TestCerts *certificates.TestCertificates
}

func (e *Env) StoreV0Config(t *testing.T) {
	config := &models.Configuration{
		IdentityCACertificates: e.TestConf.IdentityCACertificates,
		PCFAPIAddr:             e.TestConf.CFAPIAddr,
		PCFUsername:            e.TestConf.CFUsername,
		PCFPassword:            e.TestConf.CFPassword,
		LoginMaxSecNotBefore:   12,
		LoginMaxSecNotAfter:    13,
	}
	if err := storeConfig(e.Ctx, e.Storage, config); err != nil {
		t.Fatal(err)
	}
}

func (e *Env) ReadV0Config(t *testing.T) {
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
	for i, caCertRaw := range resp.Data["identity_ca_certificates"].([]string) {
		if withoutNewlines(caCertRaw) != withoutNewlines(e.TestConf.IdentityCACertificates[i]) {
			t.Fatalf("expected %q but received %q", e.TestConf.IdentityCACertificates[i], caCertRaw)
		}
	}
	if resp.Data["cf_api_addr"] != e.TestConf.CFAPIAddr {
		t.Fatalf("expected %s but received %s", e.TestConf.CFAPIAddr, resp.Data["cf_api_addr"])
	}
	if resp.Data["cf_username"] != e.TestConf.CFUsername {
		t.Fatalf("expected %s but received %s", e.TestConf.CFUsername, resp.Data["cf_username"])
	}
	if resp.Data["cf_password"] != nil {
		t.Fatalf("expected %s but received %s", "nil", resp.Data["cf_password"])
	}
}

func (e *Env) CreateConfig(t *testing.T) {
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"identity_ca_certificates":      e.TestConf.IdentityCACertificates,
			"cf_api_mutual_tls_certificate": e.TestConf.CFMutualTLSCertificate,
			"cf_api_mutual_tls_key":         e.TestConf.CFMutualTLSKey,
			"cf_api_addr":                   e.TestConf.CFAPIAddr,
			"cf_username":                   e.TestConf.CFUsername,
			"cf_password":                   e.TestConf.CFPassword,
			"cf_client_id":                  e.TestConf.CFClientID,
			"cf_client_secret":              e.TestConf.CFClientSecret,
			"cf_timeout":                    e.TestConf.CFTimeout,
			"login_max_seconds_not_before":  12,
			"login_max_seconds_not_after":   13,
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
	for i, caCertRaw := range resp.Data["identity_ca_certificates"].([]string) {
		if withoutNewlines(caCertRaw) != withoutNewlines(e.TestConf.IdentityCACertificates[i]) {
			t.Fatalf("expected %q but received %q", e.TestConf.IdentityCACertificates[i], caCertRaw)
		}
	}
	if resp.Data["cf_api_mutual_tls_certificate"] == nil && e.TestConf.CFMutualTLSCertificate != "" {
		t.Fatalf("expected cf_api_mutual_tls_certificate not to be nil but received %q", resp.Data["cf_api_mutual_tls_certificate"])
	}
	if resp.Data["cf_api_mutual_tls_key"] != nil {
		t.Fatalf("we don't expect cf_api_mutual_tls_key to be output but received %q", resp.Data["cf_api_mutual_tls_key"])
	}
	if withoutNewlines(resp.Data["cf_api_mutual_tls_certificate"].(string)) != withoutNewlines(e.TestConf.CFMutualTLSCertificate) {
		t.Fatalf("expected %q but received %q", e.TestConf.CFMutualTLSCertificate, resp.Data["cf_api_mutual_tls_certificate"])
	}
	if resp.Data["cf_api_addr"] != e.TestConf.CFAPIAddr {
		t.Fatalf("expected %s but received %s", e.TestConf.CFAPIAddr, resp.Data["cf_api_addr"])
	}
	if resp.Data["cf_username"] != e.TestConf.CFUsername {
		t.Fatalf("expected %s but received %s", e.TestConf.CFUsername, resp.Data["cf_username"])
	}
	if resp.Data["cf_password"] != nil {
		t.Fatalf("expected %s but received %s", "nil", resp.Data["cf_password"])
	}
	if resp.Data["cf_client_id"] != e.TestConf.CFClientID {
		t.Fatalf("expected %s but received %s", e.TestConf.CFClientID, resp.Data["cf_client_id"])
	}
	if resp.Data["cf_client_secret"] != nil {
		t.Fatalf("expected %s but received %s", "nil", resp.Data["cf_client_secret"])
	}
	if resp.Data["cf_timeout"] != e.TestConf.CFTimeout.Seconds() {
		t.Fatalf("expected %f but received %f", e.TestConf.CFTimeout.Seconds(), resp.Data["cf_timeout"])
	}
}

func (e *Env) UpdateConfig(t *testing.T) {
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"identity_ca_certificates": []string{"foo1", "foo2"},
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

func (e *Env) ReadUpdatedConfig(t *testing.T) {
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
	expected := []string{"foo1", "foo2"}
	for i, caCertRaw := range resp.Data["identity_ca_certificates"].([]string) {
		if withoutNewlines(caCertRaw) != withoutNewlines(expected[i]) {
			t.Fatalf("expected %q but received %q", e.TestConf.IdentityCACertificates[i], caCertRaw)
		}
	}
	if resp.Data["cf_api_addr"] != e.TestConf.CFAPIAddr {
		t.Fatalf("expected %s but received %s", e.TestConf.CFAPIAddr, resp.Data["cf_api_addr"])
	}
	if resp.Data["cf_username"] != e.TestConf.CFUsername {
		t.Fatalf("expected %s but received %s", e.TestConf.CFUsername, resp.Data["cf_username"])
	}
	if resp.Data["cf_password"] != nil {
		t.Fatalf("expected %s but received %s", "", resp.Data["cf_password"])
	}
	if resp.Data["cf_client_id"] != e.TestConf.CFClientID {
		t.Fatalf("expected %s but received %s", e.TestConf.CFClientID, resp.Data["cf_client_id"])
	}
	if resp.Data["cf_client_secret"] != nil {
		t.Fatalf("expected %s but received %s", "", resp.Data["cf_client_secret"])
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
			"disable_ip_matching":    e.TestRole.DisableIPMatching,
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
	role := &models.RoleEntry{}
	if err := entry.DecodeJSON(role); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(e.TestRole.BoundAppIDs, role.BoundAppIDs) {
		t.Fatalf("expected %s but received %s", e.TestRole.BoundAppIDs, role.BoundAppIDs)
	}
	if !reflect.DeepEqual(e.TestRole.BoundSpaceIDs, role.BoundSpaceIDs) {
		t.Fatalf("expected %s but received %s", e.TestRole.BoundSpaceIDs, role.BoundSpaceIDs)
	}
	if !reflect.DeepEqual(e.TestRole.BoundOrgIDs, role.BoundOrgIDs) {
		t.Fatalf("expected %s but received %s", e.TestRole.BoundOrgIDs, role.BoundOrgIDs)
	}
	if !reflect.DeepEqual(e.TestRole.BoundInstanceIDs, role.BoundInstanceIDs) {
		t.Fatalf("expected %s but received %s", e.TestRole.BoundInstanceIDs, role.BoundInstanceIDs)
	}
	if !reflect.DeepEqual(e.TestRole.BoundCIDRs, role.BoundCIDRs) {
		t.Fatalf("expected %s but received %s", e.TestRole.BoundCIDRs, role.BoundCIDRs)
	}
	if !reflect.DeepEqual(e.TestRole.Policies, role.Policies) {
		t.Fatalf("expected %s but received %s", e.TestRole.Policies, role.Policies)
	}
	if e.TestRole.TTL*time.Second != role.TTL {
		t.Fatalf("expected %s but received %s", e.TestRole.TTL*time.Second, role.TTL)
	}
	if e.TestRole.MaxTTL*time.Second != role.MaxTTL {
		t.Fatalf("expected %s but received %s", e.TestRole.MaxTTL*time.Second, role.MaxTTL)
	}
	if e.TestRole.Period*time.Second != role.Period {
		t.Fatalf("expected %s but received %s", e.TestRole.Period*time.Second, role.Period)
	}
	if e.TestRole.DisableIPMatching != role.DisableIPMatching {
		t.Fatalf("expected %v but received %v", e.TestRole.DisableIPMatching, role.DisableIPMatching)
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
			"disable_ip_matching":    true,
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
	role := &models.RoleEntry{}
	if err := entry.DecodeJSON(role); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(e.TestRole.BoundAppIDs, role.BoundAppIDs) {
		t.Fatalf("expected %s but received %s", e.TestRole.BoundAppIDs, role.BoundAppIDs)
	}
	if !reflect.DeepEqual([]string{}, role.BoundSpaceIDs) {
		t.Fatalf("expected %s but received %s", []string{}, role.BoundSpaceIDs)
	}
	if !reflect.DeepEqual([]string{"foo"}, role.BoundOrgIDs) {
		t.Fatalf("expected %s but received %s", []string{"foo"}, role.BoundOrgIDs)
	}
	if !reflect.DeepEqual(e.TestRole.BoundInstanceIDs, role.BoundInstanceIDs) {
		t.Fatalf("expected %s but received %s", e.TestRole.BoundInstanceIDs, role.BoundInstanceIDs)
	}
	if len(role.BoundCIDRs) != 0 {
		t.Fatalf("expected %s but received %s", []string{}, role.BoundCIDRs)
	}
	if !reflect.DeepEqual(e.TestRole.Policies, role.Policies) {
		t.Fatalf("expected %s but received %s", e.TestRole.Policies, role.Policies)
	}
	if e.TestRole.TTL*time.Second != role.TTL {
		t.Fatalf("expected %s but received %s", e.TestRole.TTL*time.Second, role.TTL)
	}
	if time.Duration(180)*time.Second != role.MaxTTL {
		t.Fatalf("expected %s but received %s", e.TestRole.MaxTTL*time.Second, role.MaxTTL)
	}
	if e.TestRole.Period*time.Second != role.Period {
		t.Fatalf("expected %s but received %s", e.TestRole.Period*time.Second, role.Period)
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

	// Convert token_type since in JSON it needs to be the corresponding uint
	resp.Data["token_type"] = logical.TokenTypeDefault

	// To reuse the logic above, convert this into a role.
	b, err := json.Marshal(resp.Data)
	if err != nil {
		t.Fatal(err)
	}
	role := &models.RoleEntry{}
	if err := json.Unmarshal(b, role); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(e.TestRole.BoundAppIDs, role.BoundAppIDs) {
		t.Fatalf("expected %s but received %s", e.TestRole.BoundAppIDs, role.BoundAppIDs)
	}
	if !reflect.DeepEqual([]string{}, role.BoundSpaceIDs) {
		t.Fatalf("expected %s but received %s", []string{}, role.BoundSpaceIDs)
	}
	if !reflect.DeepEqual([]string{"foo"}, role.BoundOrgIDs) {
		t.Fatalf("expected %s but received %s", []string{"foo"}, role.BoundOrgIDs)
	}
	if !reflect.DeepEqual(e.TestRole.BoundInstanceIDs, role.BoundInstanceIDs) {
		t.Fatalf("expected %s but received %s", e.TestRole.BoundInstanceIDs, role.BoundInstanceIDs)
	}
	if len(role.BoundCIDRs) != 0 {
		t.Fatalf("expected %s but received %s", []string{}, role.BoundCIDRs)
	}
	if !reflect.DeepEqual(e.TestRole.Policies, role.Policies) {
		t.Fatalf("expected %s but received %s", e.TestRole.Policies, role.Policies)
	}
	if time.Duration(60) != role.TTL {
		t.Fatalf("expected %s but received %s", time.Duration(60), role.TTL)
	}
	if time.Duration(180) != role.MaxTTL {
		t.Fatalf("expected %s but received %s", time.Duration(180), role.MaxTTL)
	}
	if time.Duration(300) != role.Period {
		t.Fatalf("expected %s but received %s", time.Duration(300), role.Period)
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

func (e *Env) Login(t *testing.T) {
	signingTime := time.Now()
	signatureData := &signatures.SignatureData{
		SigningTime:            signingTime,
		Role:                   "test-role",
		CFInstanceCertContents: e.TestCerts.InstanceCertificate,
	}
	signature, err := signatures.Sign(e.TestCerts.PathToInstanceKey, signatureData)
	if err != nil {
		t.Fatal(err)
	}
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"role":             "test-role",
			"signature":        signature,
			"signing_time":     signingTime.UTC().Format(signatures.TimeFormat),
			"cf_instance_cert": e.TestCerts.InstanceCertificate,
		},
		Connection: &logical.Connection{
			RemoteAddr: "10.255.181.105",
		},
	}
	resp, err := e.Backend.HandleRequest(e.Ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr:%v", resp, err)
	}

	if resp.Auth.DisplayName != cf.FoundServiceGUID {
		t.Fatalf("expected %s but received %s", cf.FoundServiceGUID, resp.Auth.DisplayName)
	}
	if len(resp.Auth.Policies) != 2 {
		t.Fatalf("expected 2 policies but received %d", len(resp.Auth.Policies))
	}
	if resp.Auth.InternalData["role"] != "test-role" {
		t.Fatalf("expected %s but received %s", "test-role", resp.Auth.InternalData["role"])
	}
	if resp.Auth.InternalData["instance_id"] != cf.FoundServiceGUID {
		t.Fatalf("expected %s but received %s", cf.FoundServiceGUID, resp.Auth.InternalData["instance_id"])
	}
	if resp.Auth.Alias.Metadata["org_id"] != cf.FoundOrgGUID {
		t.Fatalf("expected %s but received %s", cf.FoundOrgGUID, resp.Auth.Alias.Metadata["org_id"])
	}
	if resp.Auth.Alias.Metadata["app_id"] != cf.FoundAppGUID {
		t.Fatalf("expected %s but received %s", cf.FoundAppGUID, resp.Auth.Alias.Metadata["app_id"])
	}
	if resp.Auth.Alias.Metadata["space_id"] != cf.FoundSpaceGUID {
		t.Fatalf("expected %s but received %s", cf.FoundSpaceGUID, resp.Auth.Alias.Metadata["space_id"])
	}
	if resp.Auth.Alias.Metadata["org_name"] != cf.FoundOrgName {
		t.Fatalf("expected %s but received %s", cf.FoundOrgName, resp.Auth.Alias.Metadata["org_name"])
	}
	if resp.Auth.Alias.Metadata["app_name"] != cf.FoundAppName {
		t.Fatalf("expected %s but received %s", cf.FoundAppName, resp.Auth.Alias.Metadata["app_name"])
	}
	if resp.Auth.Alias.Metadata["space_name"] != cf.FoundSpaceName {
		t.Fatalf("expected %s but received %s", cf.FoundSpaceName, resp.Auth.Alias.Metadata["space_name"])
	}
	if resp.Auth.InternalData["ip_addresses"] != nil {
		t.Fatalf("expected %s but received %s", "", resp.Auth.InternalData["ip_addresses"])
	}
	if resp.Auth.Alias.Name != cf.FoundAppGUID {
		t.Fatalf("expected %s but received %s", cf.FoundServiceGUID, resp.Auth.Alias.Name)
	}
	if !resp.Auth.LeaseOptions.Renewable {
		t.Fatal("expected lease to be renewable")
	}
	if resp.Auth.LeaseOptions.TTL != time.Minute {
		t.Fatalf("expected a minute but received %s", e.TestRole.TTL)
	}
	if resp.Auth.LeaseOptions.MaxTTL != time.Minute*2 {
		t.Fatalf("expected 2 minutes but received %s", resp.Auth.LeaseOptions.MaxTTL)
	}
}

// In testing, we found that some string arrays get their trailing \n stripped when
// you use entry.DecodeJSON directly against the struct; however, the \n is immaterial
// to whether the values are useful. Rather than correct the behavior, since everything
// is functional, we decided to ignore newlines when comparing the values of strings.
func withoutNewlines(s string) string {
	return strings.Replace(s, "\n", "", -1)
}

type cfClientTest struct {
	name           string
	config         *models.Configuration
	lastConfigHash *[32]byte
	setConfigHash  bool
	cfClient       *cfclient.Client
	withMockServer bool
	wantErr        assert.ErrorAssertionFunc
}

func Test_backend_updateCFClient(t *testing.T) {
	ctx := context.Background()

	s := cf.MockServer(false, nil, map[string]int{})
	t.Cleanup(func() {
		if s != nil {
			s.Close()
		}
	})

	tests := []struct {
		name         string
		config       *models.Configuration
		modifyConfig func(*models.Configuration)
		expectErr    bool
		expectClient bool
		expectHash   bool
		initBackend  bool
		checkFunc    func(t *testing.T, b *backend, prevClient *cfclient.Client, prevHash *[32]byte)
	}{
		{
			name:         "nil-config-returns error",
			config:       nil,
			expectErr:    true,
			expectClient: false,
			expectHash:   false,
		},
		{
			name:         "initializes-new-client-and-hash",
			config:       newConfig(t),
			modifyConfig: func(c *models.Configuration) { c.CFAPIAddr = s.URL },
			expectErr:    false,
			expectClient: true,
			expectHash:   true,
		},
		{
			name:         "replaces-existing-client-but-keeps-same-hash",
			config:       newConfig(t),
			modifyConfig: func(c *models.Configuration) { c.CFAPIAddr = s.URL },
			expectErr:    false,
			expectClient: true,
			expectHash:   true,
			initBackend:  true,
			checkFunc: func(t *testing.T, b *backend, prevClient *cfclient.Client, prevHash *[32]byte) {
				require.NotEqual(t, prevClient, b.cfClient, "expected cfClient to change")
				require.Equal(t, *prevHash, *b.lastConfigHash, "expected hash to remain the same")
			},
		},
		{
			name:         "newCFClient-with-invalid-config-returns-error",
			config:       newConfig(t),
			modifyConfig: func(c *models.Configuration) { c.CFAPIAddr = "http://invalid" },
			expectErr:    true,
			expectClient: false,
			expectHash:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := &backend{}

			if tt.modifyConfig != nil && tt.config != nil {
				tt.modifyConfig(tt.config)
			}

			if tt.initBackend {
				backend.updateCFClient(ctx, tt.config)
			}

			prevClient := backend.cfClient
			prevHash := backend.lastConfigHash

			err := backend.updateCFClient(ctx, tt.config)

			if tt.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			if tt.expectClient {
				require.NotNil(t, backend.cfClient, "expected cfClient to be set")
			} else {
				require.Nil(t, backend.cfClient, "expected cfClient to remain nil")
			}

			if tt.expectHash {
				require.NotNil(t, backend.lastConfigHash, "expected lastConfigHash to be set")
			} else {
				require.Nil(t, backend.lastConfigHash, "expected lastConfigHash to remain nil")
			}

			if tt.checkFunc != nil {
				tt.checkFunc(t, backend, prevClient, prevHash)
			}
		})
	}
}

func Test_backend_newCFClient(t *testing.T) {
	t.Parallel()

	ca, _, err := GenerateCA()
	require.NoErrorf(t, err, "GenerateCA()")

	ctx := context.Background()
	tests := []cfClientTest{
		{
			name:    "invalid-nil-config",
			wantErr: assert.Error,
		},
		{
			name: "invalid-api-addr",
			config: &models.Configuration{
				CFAPIAddr:  "https://127.0.0.1:12345",
				CFUsername: "admin",
				CFPassword: "password",
			},
			wantErr: func(t assert.TestingT, err error, msgAndArgs ...any) bool {
				// expect the error returned by the call to cfclient.NewClient(), which gets the
				// /v2/info on initialization. We will need to adapt/drop this test when we
				// upgrade to v3 of the client.
				return assert.ErrorContains(t, err,
					"Could not get api /v2/info: Get", msgAndArgs...)
			},
		},
		{
			name: "invalid-ca-certificate",
			config: &models.Configuration{
				CFUsername: "admin",
				CFPassword: "password",
				CFAPICertificates: []string{
					string(ca),
					string(ca[len(ca)-1]),
				},
			},
			wantErr: func(t assert.TestingT, err error, msgAndArgs ...any) bool {
				return assert.ErrorContains(t, err,
					"failed to append CF API cert to cert pool, index=1", msgAndArgs...)
			},
		},
		{
			name: "valid-client",
			config: &models.Configuration{
				CFAPIAddr:  "https://api.example.com",
				CFUsername: "admin",
				CFPassword: "password",
				CFAPICertificates: []string{
					string(ca),
				},
			},
			withMockServer: true,
			wantErr:        assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &backend{}
			var s *httptest.Server
			if tt.withMockServer {
				require.NotNil(t, tt.config, "test %s: config is nil", tt.name)
				s = cf.MockServer(false, nil, map[string]int{})
				t.Cleanup(func() {
					if s != nil {
						s.Close()
					}
				})

				tt.config.CFAPIAddr = s.URL
			}

			got, err := b.newCFClient(ctx, tt.config)
			if !tt.wantErr(t, err, fmt.Sprintf("newCFClient(%v, %v)", ctx, tt.config)) {
				return
			}

			if err != nil {
				assert.Nilf(t, got, "newCFClient(%v, %v)", ctx, tt.config)
			} else {
				assert.NotNilf(t, got, "newCFClient(%v, %v)", ctx, tt.config)
			}

			assert.Nilf(t, b.cfClient, "newCFClient(%v, %v)", ctx, tt.config)
			assert.Nilf(t, b.lastConfigHash, "newCFClient(%v, %v)", ctx, tt.config)
			assert.Nilf(t, b.cfClient, "newCFClient(%v, %v)", ctx, tt.config)
		})
	}
}

func Test_backend_getCFClient(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	defaultClient := &cfclient.Client{
		Config: cfclient.Config{
			ApiAddress: "https://api.example.com",
		},
		Endpoint: cfclient.Endpoint{},
	}
	tests := []struct {
		name     string
		cfClient *cfclient.Client
		want     *cfclient.Client
		wantErr  assert.ErrorAssertionFunc
	}{
		{
			name:     "valid-client",
			cfClient: defaultClient,
			want:     defaultClient,
			wantErr:  assert.NoError,
		},
		{
			name:     "invalid-nil-client",
			cfClient: nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorIs(t, err, errCFClientNotInitialized, i...)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &backend{
				cfClient: tt.cfClient,
			}
			got, err := b.getCFClient(ctx)
			if !tt.wantErr(t, err, fmt.Sprintf("getCFClient(%v)", ctx)) {
				return
			}

			assert.Equalf(t, tt.want, got, "getCFClient(%v)", ctx)
			if err == nil {
				got, err = b.getCFClient(ctx)
				assert.NoErrorf(t, err, "getCFClient(%v)", ctx)
				assert.Equalf(t, tt.want, got, "getCFClient(%v)", ctx)
			}
		})
	}
}

func Test_backend_getCFClientOrRefresh(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	tests := []cfClientTest{
		{
			name:    "invalid-nil-config",
			wantErr: assert.Error,
		},
		{
			name:           "valid-config-hash-match",
			config:         newConfig(t),
			setConfigHash:  true,
			withMockServer: true,
			cfClient:       &cfclient.Client{},
			wantErr:        assert.NoError,
		},
		{
			name:           "updated-new-client",
			config:         newConfig(t),
			wantErr:        assert.NoError,
			withMockServer: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &backend{
				lastConfigHash: tt.lastConfigHash,
				cfClient:       tt.cfClient,
			}

			var s *httptest.Server
			var expectConfigHash [32]byte
			var err error

			if tt.lastConfigHash != nil && !tt.setConfigHash {
				expectConfigHash = *tt.lastConfigHash
			}

			if tt.withMockServer {
				require.NotNil(t, tt.config, "test %s: config is nil", tt.name)
				s = cf.MockServer(false, nil, map[string]int{})
				t.Cleanup(func() {
					if s != nil {
						s.Close()
					}
				})

				tt.config.CFAPIAddr = s.URL
				expectConfigHash, err = tt.config.Hash()
				if err != nil {
					require.FailNow(t, err.Error())
				}

				if tt.setConfigHash {
					b.lastConfigHash = &expectConfigHash
				}
			}

			c, err := b.getCFClientOrRefresh(ctx, tt.config)
			if !tt.wantErr(t, err, fmt.Sprintf("getCFClientOrRefresh(%v, %v)", ctx, tt.config)) {
				return
			}

			if err != nil {
				assert.Nilf(t, c, "getCFClientOrRefresh(%v, %v)", ctx, tt.config)
				assert.Nilf(t, b.lastConfigHash, "getCFClientOrRefresh(%v, %v)", ctx, tt.config)
				return
			}

			assert.Equalf(t, b.cfClient, c, "getCFClientOrRefresh(%v, %v)", ctx, tt.config)

			// test again, should not update
			c, err = b.getCFClientOrRefresh(ctx, tt.config)
			assert.NoErrorf(t, err, "getClientOrRefresh")
			assert.Equalf(t, b.cfClient, c, "getCFClientOrRefresh(%v, %v)", ctx, tt.config)
			assert.Equalf(t, expectConfigHash, *b.lastConfigHash, "getCFClientOrRefresh(%v, %v)", ctx, tt.config)
			assert.NotNilf(t, b.cfClient, "getCFClientOrRefresh(%v, %v)", ctx, tt.config)
		})
	}
}

func Test_backend_initialize(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	defaultConfig := newConfig(t)
	defaultInitReq := initReq(t, ctx, defaultConfig)

	type initializeTest struct {
		cfClientTest
		req           *logical.InitializationRequest
		name          string
		wantClientSet bool
	}

	tests := []initializeTest{
		{
			name:          "valid-server-running",
			wantClientSet: true,
			cfClientTest: cfClientTest{
				config:         newConfig(t),
				withMockServer: true,
				wantErr:        assert.NoError,
			},
		},
		{
			name:          "invalid-server-not-running",
			wantClientSet: false,
			req:           defaultInitReq,
			cfClientTest: cfClientTest{
				config:         newConfig(t),
				wantErr:        assert.NoError,
				withMockServer: false,
			},
		},
		{
			name: "invalid-nil-init-request",
			cfClientTest: cfClientTest{
				wantErr: assert.Error,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &backend{
				Backend:        &framework.Backend{},
				lastConfigHash: tt.lastConfigHash,
				cfClient:       tt.cfClient,
			}

			var s *httptest.Server
			var expectConfigHash [32]byte
			var err error

			if tt.lastConfigHash != nil && !tt.setConfigHash {
				expectConfigHash = *tt.lastConfigHash
			}

			if tt.withMockServer {
				require.NotNil(t, tt.config, "test %s: config is nil", tt.name)
				s = cf.MockServer(false, nil, map[string]int{})
				t.Cleanup(func() {
					if s != nil {
						s.Close()
					}
				})

				tt.config.CFAPIAddr = s.URL
				expectConfigHash, err = tt.config.Hash()
				if err != nil {
					require.FailNow(t, err.Error())
				}

				if tt.req == nil {
					tt.req = initReq(t, ctx, tt.config)
				}
			}

			err = b.initialize(ctx, tt.req)
			if !tt.wantErr(t, err, fmt.Sprintf("initialize(%v, %v)", ctx, tt.config)) {
				return
			}

			if tt.wantClientSet {
				assert.NotNilf(t, b.cfClient, "initialize(%v, %v)", ctx, tt.config)
				assert.NotNilf(t, b.lastConfigHash, "initialize(%v, %v)", ctx, tt.config)
				assert.Equalf(t, expectConfigHash, *b.lastConfigHash, "initialize(%v, %v)", ctx, tt.config)
			} else {
				assert.Nilf(t, b.cfClient, "initialize(%v, %v)", ctx, tt.config)
				assert.Nilf(t, b.lastConfigHash, "initialize(%v, %v)", ctx, tt.config)
			}
		})
	}
}

func newConfig(t *testing.T) *models.Configuration {
	t.Helper()
	return &models.Configuration{
		Version:    1,
		CFAPIAddr:  "https://api.example.com",
		CFUsername: "admin",
		CFPassword: "password",
	}
}

func initReq(t *testing.T, ctx context.Context, config *models.Configuration) *logical.InitializationRequest {
	t.Helper()
	entry, err := logical.StorageEntryJSON(configStorageKey, config)
	require.NoError(t, err)
	storage := &logical.InmemStorage{}
	require.NoError(t, storage.Put(ctx, entry))
	return &logical.InitializationRequest{
		Storage: storage,
	}
}
