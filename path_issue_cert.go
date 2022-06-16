package pki

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/fatih/structs"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"vault-plugin-hydrant-pki/pkg/hydrant"
)

func pathIssue(b *Backend) *framework.Path {
	ret := &framework.Path{
		Pattern: "issue",
		Fields: map[string]*framework.FieldSchema{
			"cn": {
				Type:        framework.TypeString,
				Description: "Specifies the CN for the certificate.",
				Required:    true,
			},
			"ttl": {
				Type:        framework.TypeInt,
				Description: "Specifies the TTL for the certificate (in days). Defaults to 1 year (365 days) if not specified.",
				Default:     1,
			},
			"sans": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Specifies the SANs for the certificate. Comma separated string values e.g.: sans='test0.domain.com, test1.domain.com'",
			},
			"dl": {
				Type:        framework.TypeString,
				Description: "Specifies the distribution list for the owner of the certificate.",
				Required:    true,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleIssueCert,
				Summary:  "Issue certificate from HydrantID.",
			},
		},
		HelpSynopsis:    pathIssueHelpSyn,
		HelpDescription: pathIssueHelpDesc,
	}

	return ret
}

const pathIssueHelpSyn = `
Request a certificate with the provided details.
`

const pathIssueHelpDesc = `
This path allows requesting a certificate to be issued. 
The certificate will only be issued if the requested details are allowed by the hydrant policy.
This path returns a certificate with its private key.
`

func pathRenew(b *Backend) *framework.Path {
	ret := &framework.Path{
		Pattern: "renew/(?P<id>([a-fA-F0-9]+-)+[a-fA-F0-9]+)",
		Fields: map[string]*framework.FieldSchema{
			"id": {
				Type:        framework.TypeString,
				Description: "Specifies the ID for the certificate.",
				Required:    true,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathRenew,
				Summary:  "Renew certificate from HydrantID.",
			},
		},
		HelpSynopsis:    pathRenewHelpSyn,
		HelpDescription: pathRenewHelpDesc,
	}

	return ret
}

const pathRenewHelpSyn = `
Request a certificate renewal for the provided id.
`

const pathRenewHelpDesc = `
Request a certificate renewal for the provided id.
This requires that the policy used to issue this certificate initially allows for csr reuse. 
Otherwise, this will fail.
`

func (b *Backend) handleIssueCert(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if req.ClientToken == "" {
		return nil, fmt.Errorf("client token empty")
	}

	if data.Get("cn") == nil || data.Get("cn") == "" {
		return nil, errors.New("cn is empty")
	}
	if data.Get("dl") == nil || data.Get("dl") == "" {
		return nil, errors.New("distribution list dl is empty")
	}
	cn := data.Get("cn").(string)
	ttl := data.Get("ttl").(int)
	sans := data.Get("sans").([]string)
	dl := data.Get("dl").(string)

	hydrantClient, err := b.GetHydrantClient(ctx, req.Storage)
	if err != nil {
		b.Backend.Logger().Error(err.Error())
		return nil, err
	}

	certificate, err := hydrantClient.IssueCertificate(b.Logger(), &hydrant.IssueCertRequest{
		CN:   cn,
		TTL:  ttl,
		SANS: sans,
		DL:   dl,
	})
	if err != nil {
		return nil, err
	}

	buf, err := json.Marshal(certificate)
	if err != nil {
		return nil, errwrap.Wrapf("json encoding failed: {{err}}", err)
	}

	_ = req.Storage.Put(ctx, &logical.StorageEntry{
		Key:   "certs/" + certificate.Id,
		Value: buf,
	})

	// Generate the response
	resp := &logical.Response{
		Data: structs.Map(certificate),
	}
	return resp, nil
}

func (b *Backend) pathRenew(ctx context.Context, request *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	id := data.Get("id").(string)
	b.Backend.Logger().Info("pathRenew id: " + id)

	hydrantClient, err := b.GetHydrantClient(ctx, request.Storage)
	if err != nil {
		b.Backend.Logger().Error(err.Error())
		return nil, err
	}
	renewedCert, err := hydrantClient.RenewCert(b.Logger(), id)
	if err != nil {
		return nil, err
	}

	resp := &logical.Response{
		Data: structs.Map(renewedCert),
	}

	return resp, nil
}
