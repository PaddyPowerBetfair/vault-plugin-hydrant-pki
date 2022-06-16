package pki

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"testing"
	"vault-plugin-hydrant-pki/pkg/hydrant"
)

// TestRevokePath tests the revoke path
func TestRevoke_Path(t *testing.T) {
	fmt.Println("testing revoke certificate!")
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t, &hydrant.MockClient{})
	revokeData := map[string]interface{}{
		"id": "123-321",
	}
	issueReq := &logical.Request{
		Operation:   logical.DeleteOperation,
		Path:        "revoke/123-321",
		Storage:     storage,
		Data:        revokeData,
		ClientToken: "sample",
	}

	resp, err = b.HandleRequest(context.Background(), issueReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}
	assert.Equal(t, resp.Data["revocationStatus"], "Revoked", "Not equal!")
}
