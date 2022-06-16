package pki

import (
	"context"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"vault-plugin-hydrant-pki/pkg/hydrant"
)

func pathRevoke(b *Backend) *framework.Path {
	return &framework.Path{
		Pattern: `revoke/(?P<id>([a-fA-F0-9]+-)+[a-fA-F0-9]+)`,
		Fields: map[string]*framework.FieldSchema{
			"id": {
				Type:        framework.TypeString,
				Description: `Certificate id`,
			},
			"reason": {
				Type:        framework.TypeInt,
				Description: `Certificate revocation reason`,
			},
			"issuerDN": {
				Type:        framework.TypeString,
				Description: `Certificate revocation issuerDN`,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathRevokeCert,
				Summary:  "Revoke certificate from vault and hydrant.",
			},
		},

		HelpSynopsis:    pathRevokeHelpSyn,
		HelpDescription: pathRevokeHelpDesc,
	}
}

const pathRevokeHelpSyn = `
Revoke a certificate.
`

const pathRevokeHelpDesc = `
This allows certificates to be revoked. You will need to provide a certificate ID and a reason or a serial number and the issuer DN.
`

func (b *Backend) pathRevokeCert(ctx context.Context, request *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	id := data.Get("id").(string)
	reason := data.Get("reason").(int)
	issuerDN := data.Get("issuerDN").(string)
	b.Backend.Logger().Info("pathRevokeCert called id: " + id + " reason:")

	hydrantClient, err := b.GetHydrantClient(ctx, request.Storage)
	if err != nil {
		b.Backend.Logger().Error(err.Error())
		return nil, err
	}

	revocationResponse, err := hydrantClient.RevokeCert(b.Backend.Logger(), &hydrant.RevocationRequest{
		ID:       id,
		Reason:   reason,
		IssuerDN: issuerDN,
	})

	if err != nil {
		return nil, err
	}

	rawData := map[string]interface{}{
		"id":               revocationResponse.Id,
		"revocationReason": revocationResponse.RevocationReason,
		"revocationStatus": revocationResponse.RevocationStatus,
		"revocationDate":   revocationResponse.RevocationDate,
	}

	// Generate the response
	result := &logical.Response{
		Data: rawData,
	}
	err = request.Storage.Delete(ctx, "certs/"+id)
	if err != nil {
		b.Backend.Logger().Error("Server pathRevokeCert delete cert from storage failure!")
		return nil, err
	}
	return result, nil
}
