package pki

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"testing"
	"vault-plugin-hydrant-pki/pkg/hydrant"
)

func verifyKeyPair(privateKey, publicKey string) bool {
	block, _ := pem.Decode([]byte(privateKey))
	key, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	pubBlock, _ := pem.Decode([]byte(publicKey))
	pubKey, _ := x509.ParsePKCS1PublicKey(pubBlock.Bytes)
	return key.PublicKey.Equal(pubKey)
}

func TestIssue_Cert(t *testing.T) {

	fmt.Println("testing issue certificate!")
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t, &hydrant.MockClient{OutCert: hydrant.MockCert3})
	IssueData := map[string]interface{}{
		"cn":  "test.com",
		"ttl": 10,
		"dl":  "something@something.com",
	}
	issueReq := &logical.Request{
		Operation:   logical.UpdateOperation,
		Path:        "issue",
		Storage:     storage,
		Data:        IssueData,
		ClientToken: "sample",
	}

	resp, err = b.HandleRequest(context.Background(), issueReq)
	entry, _ := storage.Get(context.Background(), "certs/"+resp.Data["Id"].(string))
	var rawData map[string]interface{}

	jsonErr := jsonutil.DecodeJSON(entry.Value, &rawData)
	if jsonErr != nil {
		fmt.Println("Error when decoding json")
	}

	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	match := verifyKeyPair(resp.Data["PrivateKey"].(string), resp.Data["PublicKey"].(string))

	assert.Equal(t, rawData["id"].(string), "123", "Not equal!")
	assert.Equal(t, match, true, "Not equal!")
	assert.Equal(t, resp.Data["CommonName"], "test.com", "Not equal!")
}

func TestRenew_Cert(t *testing.T) {

	fmt.Println("testing issue certificate!")
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t, &hydrant.MockClient{OutRenewResponse: hydrant.MockRenewResp})
	RenewData := map[string]interface{}{
		"id": "123-321",
	}
	RenewReq := &logical.Request{
		Operation:   logical.UpdateOperation,
		Path:        "renew/123-321",
		Storage:     storage,
		Data:        RenewData,
		ClientToken: "sample",
	}

	resp, err = b.HandleRequest(context.Background(), RenewReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

	assert.Equal(t, resp.Data["CertificateId"].(string), "1111", "Not equal!")
	assert.Equal(t, resp.Data["IssuanceStatus"].(string), "renew", "Not equal!")
	assert.Equal(t, resp.Data["RevocationStatus"].(string), "revoked", "Not equal!")
	assert.Equal(t, resp.Data["Id"].(string), "123-321", "Not equal!")
}
