package pki

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"testing"
	"vault-plugin-hydrant-pki/pkg/hydrant"
)

// TestPolicyFetch_Path tests the fetch policy path
func TestPolicyFetch_Path(t *testing.T) {
	fmt.Println("testing fetch policy!")
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t, &hydrant.MockClient{})
	fetchPolicyData := map[string]interface{}{
		"id": "123-321",
	}
	issueReq := &logical.Request{
		Operation:   logical.ReadOperation,
		Path:        "policy/123-321",
		Storage:     storage,
		Data:        fetchPolicyData,
		ClientToken: "sample",
	}

	resp, err = b.HandleRequest(context.Background(), issueReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}
	assert.Equal(t, resp.Data["Id"], "123-321", "Not equal!")
	assert.Equal(t, resp.Data["Name"], "MockPol1", "Not equal!")
}

// TestPoliciesFetch_Path tests the fetch policies path
func TestPoliciesFetch_Path(t *testing.T) {
	fmt.Println("testing fetch policy!")
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t, &hydrant.MockClient{})
	fetchPoliciesData := map[string]interface{}{
		"policies": "123-321",
	}
	issueReq := &logical.Request{
		Operation:   logical.ReadOperation,
		Path:        "policies",
		Storage:     storage,
		Data:        fetchPoliciesData,
		ClientToken: "sample",
	}

	resp, err = b.HandleRequest(context.Background(), issueReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}
	assert.Equal(t, resp.Data["Id"], nil, "Not equal!")
}
