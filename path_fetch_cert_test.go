package pki

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"testing"
	"vault-plugin-hydrant-pki/pkg/hydrant"
)

// TestCertFetch_Cert tests the fetch hydrant cert path
func TestCertFetch_Path(t *testing.T) {
	fmt.Println("testing fetch hydrant cert!")
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t, &hydrant.MockClient{OutCert: hydrant.MockCert4})
	fetchCertificateData := map[string]interface{}{
		"id": "656462c5-a942-43bb-95bc-38a9adeb40b6",
	}
	issueReq := &logical.Request{
		Operation:   logical.ReadOperation,
		Path:        "certh/656462c5-a942-43bb-95bc-38a9adeb40b6",
		Storage:     storage,
		Data:        fetchCertificateData,
		ClientToken: "sample",
	}

	resp, err = b.HandleRequest(context.Background(), issueReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}
	assert.Equal(t, resp.Data["Id"], "656462c5-a942-43bb-95bc-38a9adeb40b6", "Not equal!")
	assert.Equal(t, resp.Data["CommonName"], "ade.dev.endpoint", "Not equal!")
}

// TestCertsFetch_Certs tests the fetch hydrant certs path
func TestCertsFetch_Path(t *testing.T) {
	fmt.Println("testing fetch Hydrant certs!")
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t, &hydrant.MockClient{})
	fetchCertificatesData := map[string]interface{}{
		"Count": 2,
	}
	issueReq := &logical.Request{
		Operation:   logical.ReadOperation,
		Path:        "certsh",
		Storage:     storage,
		Data:        fetchCertificatesData,
		ClientToken: "sample",
	}
	resp, err = b.HandleRequest(context.Background(), issueReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}
	assert.Equal(t, resp.Data["Count"], 5, "Not equal!")
}

// TestCertsVaultFetch_Certs
func TestCertsVaultFetch_Path(t *testing.T) {
	fmt.Println("testing fetch certs!")
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t, &hydrant.MockClient{})

	issueReq := &logical.Request{
		Operation:   logical.ReadOperation,
		Path:        "certs",
		Storage:     storage,
		ClientToken: "sample",
	}

	resp, err = b.HandleRequest(context.Background(), issueReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Errorf("bad: err: %v resp: %#v", err, resp)
	}
	assert.Equal(t, resp.Data == nil, false, nil)
}

// TestCertPemFetch
func TestCertPemFetch_Path(t *testing.T) {
	fmt.Println("testing fetch CertPem!")
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t, &hydrant.MockClient{})

	issueReq := &logical.Request{
		Operation:   logical.ReadOperation,
		Path:        "certpem/656462c5-a942-43bb-95bc-38a9adeb40b6",
		Storage:     storage,
		ClientToken: "sample",
	}

	resp, err = b.HandleRequest(context.Background(), issueReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}
	assert.Equal(t, resp.Data["pem"], "ade.test", "Not equal!")
}
