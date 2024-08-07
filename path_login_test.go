// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cf

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
	"golang.org/x/net/context"

	"github.com/hashicorp/vault-plugin-auth-cf/models"
)

func TestResolveRole(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	storage := &logical.InmemStorage{}

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
	role := "testrole"

	// Put dummy role entry in to satisfy existence check
	entry, err := logical.StorageEntryJSON(roleStoragePrefix+role, &models.RoleEntry{})
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.Put(ctx, entry); err != nil {
		t.Fatal(err)
	}

	loginData := map[string]interface{}{
		"role": role,
	}
	loginReq := &logical.Request{
		Operation: logical.ResolveRoleOperation,
		Path:      "login",
		Storage:   storage,
		Data:      loginData,
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	}

	resp, err := backend.HandleRequest(context.Background(), loginReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["role"] != role {
		t.Fatalf("Role was not as expected. Expected %s, received %s", role, resp.Data["role"])
	}
}

func TestResolveRole_RoleDoesNotExist(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	storage := &logical.InmemStorage{}

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
	role := "testrole"

	loginData := map[string]interface{}{
		"role": role,
	}
	loginReq := &logical.Request{
		Operation: logical.ResolveRoleOperation,
		Path:      "login",
		Storage:   storage,
		Data:      loginData,
		Connection: &logical.Connection{
			RemoteAddr: "127.0.0.1",
		},
	}

	resp, err := backend.HandleRequest(context.Background(), loginReq)
	if resp == nil && !resp.IsError() {
		t.Fatalf("Response was not an error: err:%v resp:%#v", err, resp)
	}

	errString, ok := resp.Data["error"].(string)
	if !ok {
		t.Fatal("Error not part of response.")
	}

	if !strings.Contains(errString, "invalid role name") {
		t.Fatalf("Error was not due to invalid role name. Error: %s", errString)
	}
}

func TestMatchesIPAddr(t *testing.T) {
	t.Parallel()

	certIP := net.ParseIP("10.255.181.105")
	if !matchesIPAddress("10.255.181.105/32", certIP) {
		t.Fatal("should match")
	}
	if !matchesIPAddress("10.255.181.105", certIP) {
		t.Fatal("should match")
	}
	if matchesIPAddress("127.0.0.1/32", certIP) {
		t.Fatal("shouldn't match")
	}
	if matchesIPAddress("127.0.0.1", certIP) {
		t.Fatal("shouldn't match")
	}
	if matchesIPAddress("", certIP) {
		t.Fatal("shouldn't match")
	}
}

func TestMeetsBoundConstraints(t *testing.T) {
	t.Parallel()

	if !meetsBoundConstraints("fizz", []string{"fizz", "buzz"}) {
		t.Fatal("should meet constraints")
	}
	if !meetsBoundConstraints("fizz", []string{}) {
		t.Fatal("should meet constraints")
	}
	if meetsBoundConstraints("foo", []string{"fizz", "buzz"}) {
		t.Fatal("shouldn't meet constraints")
	}
	if meetsBoundConstraints("", []string{"fizz", "buzz"}) {
		t.Fatal("shouldn't meet constraints")
	}
}
