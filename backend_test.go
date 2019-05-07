package pcf

import (
	"context"
	"io/ioutil"
	"testing"

	"github.com/hashicorp/vault/logical"
)

func TestBackend(t *testing.T) {
	ctx := context.Background()
	storage := &logical.InmemStorage{}

	caCertBytes, err := ioutil.ReadFile("fixtures/fake/ca.crt")
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
	})
	if err != nil {
		t.Fatal(err)
	}

	env := &Env{
		Ctx:      ctx,
		Storage:  storage,
		Backend:  backend,
		TestConf: testConf,
	}
	t.Run("create config", env.CreateConfig)
	t.Run("read config", env.ReadConfig)
	t.Run("delete config", env.DeleteConfig)
}

type Env struct {
	Ctx     context.Context
	Storage logical.Storage

	Backend  logical.Backend
	TestConf *Configuration
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
		t.Fatal("expected nil response to represent a 204")
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
}
