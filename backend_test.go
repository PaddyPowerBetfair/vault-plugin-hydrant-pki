package pki

import (
	"context"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
	"vault-plugin-hydrant-pki/pkg/hydrant"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestBackend(t *testing.T) {
	fmt.Println("testing backend!")
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	_, err := Factory(context.TODO(), &logical.BackendConfig{})
	if err != nil {
		return
	}
}

func TestBackend_IssueCert(t *testing.T) {
	fmt.Println("testing issue certificate!")
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t, &hydrant.MockClient{})

	issueData := map[string]interface{}{
		"cn": "test.com",
		"dl": "something@something.com",
	}
	issueReq := &logical.Request{
		Operation:   logical.UpdateOperation,
		Path:        "issue",
		Storage:     storage,
		Data:        issueData,
		ClientToken: "sample",
	}

	resp, err = b.HandleRequest(context.Background(), issueReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}
	assert.Equal(t, resp.Data["Id"], "123-321", "Not equal!")
}

func TestBackend_ReadConfig(t *testing.T) {
	fmt.Println("testing read configuration!")
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t, &hydrant.MockClient{})

	issueReq := &logical.Request{
		Operation:   logical.ReadOperation,
		Path:        "config",
		Storage:     storage,
		ClientToken: "sample",
	}

	resp, err = b.HandleRequest(context.Background(), issueReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}
	assert.Equal(t, resp.Data["url"], "https://acm-stage.hydrantid.com/api/v2", "Not equal!")
}
