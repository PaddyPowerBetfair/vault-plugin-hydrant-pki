package pki

import (
	"context"
	"github.com/hashicorp/vault/sdk/logical"
	"testing"
	"vault-plugin-hydrant-pki/pkg/hydrant"
)

type TestCreds struct {
	ID       string
	Key      string
	Url      string
	PolicyId string
}

func loadHydrantTestCreds() (*TestCreds, error) {
	return &TestCreds{
		ID:       "id",
		Key:      "key",
		Url:      "https://acm-stage.hydrantid.com/api/v2",
		PolicyId: "test-policy",
	}, nil

}

func createBackendWithStorage(t *testing.T, mc *hydrant.MockClient) (*Backend, logical.Storage) {
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}

	returnMock := func(cc *hydrant.ClientConfig) (hydrant.Client, error) {

		return mc, nil
	}
	var err error
	b, _ := newBackend(config, returnMock)
	err = b.Setup(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	setupHydrantClient(t, b, config.StorageView)

	return b, config.StorageView
}

func setupHydrantClient(t *testing.T, b *Backend, storage logical.Storage) {
	tc, err := loadHydrantTestCreds()
	if err != nil {
		t.Fatalf("bad: err: %v", err)
	}
	authData := map[string]interface{}{
		"id":       tc.ID,
		"key":      tc.Key,
		"url":      tc.Url,
		"policyId": tc.PolicyId,
	}

	authReq := &logical.Request{
		Operation:   logical.UpdateOperation,
		Path:        "config/authn",
		Storage:     storage,
		Data:        authData,
		ClientToken: "apple",
	}

	resp, err := b.HandleRequest(context.Background(), authReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}
}
