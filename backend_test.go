package pcf

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault-plugin-auth-pcf/models"
	"github.com/hashicorp/vault-plugin-auth-pcf/signatures"
	"github.com/hashicorp/vault-plugin-auth-pcf/testing/certificates"
	"github.com/hashicorp/vault-plugin-auth-pcf/testing/pcf"
	"github.com/hashicorp/vault/sdk/helper/parseutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func TestBackend(t *testing.T) {
	ctx := context.Background()
	storage := &logical.InmemStorage{}

	testCerts, err := certificates.Generate(pcf.FoundServiceGUID, pcf.FoundOrgGUID, pcf.FoundSpaceGUID, pcf.FoundAppGUID, "10.255.181.105")
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

	pcfServer := pcf.MockServer(false)
	defer pcfServer.Close()

	testConf := &models.Configuration{
		IdentityCACertificates: []string{testCerts.CACertificate, string(invalidCaCertBytes)},
		PCFAPIAddr:             pcfServer.URL,
		PCFUsername:            pcf.AuthUsername,
		PCFPassword:            pcf.AuthPassword,
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
			BoundAppIDs:      []string{pcf.FoundAppGUID},
			BoundSpaceIDs:    []string{pcf.FoundSpaceGUID},
			BoundOrgIDs:      []string{pcf.FoundOrgGUID},
			BoundInstanceIDs: []string{pcf.FoundServiceGUID},
			BoundCIDRs:       parsedCIDRs,
			Policies:         []string{"default", "foo"},
			TTL:              60,
			MaxTTL:           2 * 60,
			Period:           5 * 60,
		},
		TestCerts: testCerts,
	}
	// Exercise all the endpoints.
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
	t.Run("login", env.LoginSigV0)
	t.Run("login", env.LoginSigV1)
}

type Env struct {
	Ctx     context.Context
	Storage logical.Storage

	Backend   logical.Backend
	TestConf  *models.Configuration
	TestRole  *models.RoleEntry
	TestCerts *certificates.TestCertificates
}

func (e *Env) CreateConfig(t *testing.T) {
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"identity_ca_certificates":     e.TestConf.IdentityCACertificates,
			"pcf_api_addr":                 e.TestConf.PCFAPIAddr,
			"pcf_username":                 e.TestConf.PCFUsername,
			"pcf_password":                 e.TestConf.PCFPassword,
			"login_max_seconds_not_before": 12,
			"login_max_seconds_not_after":  13,
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
	if resp.Data["pcf_api_addr"] != e.TestConf.PCFAPIAddr {
		t.Fatalf("expected %s but received %s", e.TestConf.PCFAPIAddr, resp.Data["pcf_api_addr"])
	}
	if resp.Data["pcf_username"] != e.TestConf.PCFUsername {
		t.Fatalf("expected %s but received %s", e.TestConf.PCFUsername, resp.Data["pcf_username"])
	}
	if resp.Data["pcf_password"] != nil {
		t.Fatalf("expected %s but received %s", "nil", resp.Data["pcf_password"])
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

func (e *Env) LoginSigV0(t *testing.T) {
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

	if resp.Auth.DisplayName != pcf.FoundServiceGUID {
		t.Fatalf("expected %s but received %s", pcf.FoundServiceGUID, resp.Auth.DisplayName)
	}
	if len(resp.Auth.Policies) != 2 {
		t.Fatalf("expected 2 policies but received %d", len(resp.Auth.Policies))
	}
	if resp.Auth.InternalData["role"] != "test-role" {
		t.Fatalf("expected %s but received %s", "test-role", resp.Auth.InternalData["role"])
	}
	if resp.Auth.InternalData["instance_id"] != pcf.FoundServiceGUID {
		t.Fatalf("expected %s but received %s", pcf.FoundServiceGUID, resp.Auth.InternalData["instance_id"])
	}
	if resp.Auth.Alias.Metadata["org_id"] != pcf.FoundOrgGUID {
		t.Fatalf("expected %s but received %s", pcf.FoundOrgGUID, resp.Auth.Alias.Metadata["org_id"])
	}
	if resp.Auth.Alias.Metadata["app_id"] != pcf.FoundAppGUID {
		t.Fatalf("expected %s but received %s", pcf.FoundAppGUID, resp.Auth.Alias.Metadata["app_id"])
	}
	if resp.Auth.Alias.Metadata["space_id"] != pcf.FoundSpaceGUID {
		t.Fatalf("expected %s but received %s", pcf.FoundSpaceGUID, resp.Auth.Alias.Metadata["space_id"])
	}
	if resp.Auth.InternalData["ip_addresses"] != nil {
		t.Fatalf("expected %s but received %s", "", resp.Auth.InternalData["ip_addresses"])
	}
	if resp.Auth.Alias.Name != pcf.FoundAppGUID {
		t.Fatalf("expected %s but received %s", pcf.FoundServiceGUID, resp.Auth.Alias.Name)
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

func (e *Env) LoginSigV1(t *testing.T) {
	signingTime := time.Now()
	signatureData := &signatures.SignatureData{
		SigningTime:            signingTime,
		Role:                   "test-role",
		CFInstanceCertContents: e.TestCerts.InstanceCertificate,
		Version:                1,
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
			"role":              "test-role",
			"signature":         signature,
			"signing_time":      signingTime.UTC().Format(signatures.TimeFormat),
			"cf_instance_cert":  e.TestCerts.InstanceCertificate,
			"signature_version": 1,
		},
		Connection: &logical.Connection{
			RemoteAddr: "10.255.181.105",
		},
	}
	resp, err := e.Backend.HandleRequest(e.Ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr:%v", resp, err)
	}

	if resp.Auth.DisplayName != pcf.FoundServiceGUID {
		t.Fatalf("expected %s but received %s", pcf.FoundServiceGUID, resp.Auth.DisplayName)
	}
	if len(resp.Auth.Policies) != 2 {
		t.Fatalf("expected 2 policies but received %d", len(resp.Auth.Policies))
	}
	if resp.Auth.InternalData["role"] != "test-role" {
		t.Fatalf("expected %s but received %s", "test-role", resp.Auth.InternalData["role"])
	}
	if resp.Auth.InternalData["instance_id"] != pcf.FoundServiceGUID {
		t.Fatalf("expected %s but received %s", pcf.FoundServiceGUID, resp.Auth.InternalData["instance_id"])
	}
	if resp.Auth.Alias.Metadata["org_id"] != pcf.FoundOrgGUID {
		t.Fatalf("expected %s but received %s", pcf.FoundOrgGUID, resp.Auth.Alias.Metadata["org_id"])
	}
	if resp.Auth.Alias.Metadata["app_id"] != pcf.FoundAppGUID {
		t.Fatalf("expected %s but received %s", pcf.FoundAppGUID, resp.Auth.Alias.Metadata["app_id"])
	}
	if resp.Auth.Alias.Metadata["space_id"] != pcf.FoundSpaceGUID {
		t.Fatalf("expected %s but received %s", pcf.FoundSpaceGUID, resp.Auth.Alias.Metadata["space_id"])
	}
	if resp.Auth.InternalData["ip_addresses"] != nil {
		t.Fatalf("expected %s but received %s", "", resp.Auth.InternalData["ip_addresses"])
	}
	if resp.Auth.Alias.Name != pcf.FoundAppGUID {
		t.Fatalf("expected %s but received %s", pcf.FoundServiceGUID, resp.Auth.Alias.Name)
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
