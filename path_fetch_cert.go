package pki

import (
	"context"
	"github.com/fatih/structs"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathFetchCertificates(b *Backend) *framework.Path {
	return &framework.Path{
		Pattern: `certs`,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathFetchCertList,
				Summary:  "Fetch certificates from Vault.",
			},
		},

		HelpSynopsis:    pathFetchCertsHelpSyn,
		HelpDescription: pathFetchCertsHelpDesc,
	}
}

func (b *Backend) pathFetchCertList(ctx context.Context, req *logical.Request, data *framework.FieldData) (response *logical.Response, retErr error) {
	entries, err := req.Storage.List(ctx, "certs/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

const pathFetchCertsHelpSyn = `
Fetch the certificate ids stored in Vault.
`

const pathFetchCertsHelpDesc = `
Fetch the certificate ids stored in Vault.
This will display the list of certificate ids from Vault.
`

func pathFetchCertificate(b *Backend) *framework.Path {
	return &framework.Path{
		Pattern: `cert/(?P<id>([a-fA-F0-9]+-)+[a-fA-F0-9]+)`,
		Fields: map[string]*framework.FieldSchema{
			"id": {
				Type:        framework.TypeString,
				Description: `Certificate id`,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathFetchCert,
				Summary:  "Fetch certificate from vault.",
			},
		},

		HelpSynopsis:    pathFetchCertHelpSyn,
		HelpDescription: pathFetchCertHelpDesc,
	}
}

const pathFetchCertHelpSyn = `
Fetch a certificate from Vault.
`

const pathFetchCertHelpDesc = `
Fetch a certificate from Vault.
This will display all the information about the certificate with the given id from Vault.
`

func pathFetchCertificatePem(b *Backend) *framework.Path {
	return &framework.Path{
		Pattern: `certpem/(?P<id>([a-fA-F0-9]+-)+[a-fA-F0-9]+)`,
		Fields: map[string]*framework.FieldSchema{
			"id": {
				Type:        framework.TypeString,
				Description: `Certificate id`,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathFetchCertPem,
				Summary:  "Fetch certificate with chain from Hydrant.",
			},
		},

		HelpSynopsis:    pathFetchCertPemHelpSyn,
		HelpDescription: pathFetchCertPemHelpDesc,
	}
}

const pathFetchCertPemHelpSyn = `
Fetch a certificate with chain from Hydrant.
`

const pathFetchCertPemHelpDesc = `
Fetch a certificate with chain from hydrant.
This will display all the certificate chain in pem format for the given id from Hydrant.
`

func pathFetchCertificateHydrant(b *Backend) *framework.Path {
	return &framework.Path{
		Pattern: `certh/(?P<id>([a-fA-F0-9]+-)+[a-fA-F0-9]+)`,
		Fields: map[string]*framework.FieldSchema{
			"id": {
				Type:        framework.TypeString,
				Description: `Certificate id`,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathFetchCertHydrant,
				Summary:  "Fetch certificate from hydrant.",
			},
		},

		HelpSynopsis:    pathFetchCerthHelpSyn,
		HelpDescription: pathFetchCerthHelpDesc,
	}
}

const pathFetchCerthHelpSyn = `
Fetch a certificate from Hydrant.
`

const pathFetchCerthHelpDesc = `
Fetch a certificate from Hydrant.
This will display all the information about the certificate with the given id from Hydrant.
`

func pathFetchCertificatesHydrant(b *Backend) *framework.Path {
	return &framework.Path{
		Pattern: `certsh`,
		//todo add params for filters
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathFetchCertsHydrant,
				Summary:  "Fetch certificates from hydrant.",
			},
		},

		HelpSynopsis:    pathFetchCertshHelpSyn,
		HelpDescription: pathFetchCertshHelpDesc,
	}
}

const pathFetchCertshHelpSyn = `
Fetch the certificates from Hydrant.
`

const pathFetchCertshHelpDesc = `
Fetch the certificates from Hydrant.
This will display all the information about the certificates from Hydrant.
`

func (b *Backend) pathFetchCert(ctx context.Context, request *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	id := data.Get("id").(string)
	b.Backend.Logger().Info("pathFetchCert id: " + id)
	entry, err := request.Storage.Get(ctx, "certs/"+id)
	if err != nil {
		b.Backend.Logger().Error("Server pathFetchCert fetch from storage failure!")
		return nil, err
	}
	if entry == nil {
		b.Backend.Logger().Error("Server pathFetchCert fetch from storage empty entry!")
		return nil, nil
	}

	var rawData map[string]interface{}

	if err := jsonutil.DecodeJSON(entry.Value, &rawData); err != nil {
		b.Backend.Logger().Error("Server pathFetchCert fetch from storage unmarshal error!")
		return nil, errwrap.Wrapf("json decoding failed: {{err}}", err)
	}

	resp := &logical.Response{
		Data: rawData,
	}

	return resp, nil
}

func (b *Backend) pathFetchCertHydrant(ctx context.Context, request *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	id := data.Get("id").(string)
	b.Backend.Logger().Info("pathFetchCert id: " + id)

	hydrantClient, err := b.GetHydrantClient(ctx, request.Storage)
	if err != nil {
		b.Backend.Logger().Error(err.Error())
		return nil, err
	}
	certificate, err := hydrantClient.GetCert(b.Logger(), id)
	if err != nil {
		return nil, err
	}

	resp := &logical.Response{
		Data: structs.Map(certificate),
	}

	return resp, nil
}

func (b *Backend) pathFetchCertPem(ctx context.Context, request *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	id := data.Get("id").(string)
	b.Backend.Logger().Info("pathFetchCertPem id: " + id)

	hydrantClient, err := b.GetHydrantClient(ctx, request.Storage)
	if err != nil {
		b.Backend.Logger().Error(err.Error())
		return nil, err
	}
	certificate, err := hydrantClient.GetCertPem(b.Logger(), id)
	if err != nil {
		return nil, err
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"pem": certificate,
		},
	}

	return resp, nil
}

func (b *Backend) pathFetchCertsHydrant(ctx context.Context, request *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.Backend.Logger().Info("pathFetchCerts enter!")
	hydrantClient, err := b.GetHydrantClient(ctx, request.Storage)
	if err != nil {
		b.Backend.Logger().Error(err.Error())
		return nil, err
	}
	certificates, err := hydrantClient.GetCerts(b.Logger(), nil)
	if err != nil {
		return nil, err
	}

	resp := &logical.Response{
		Data: structs.Map(certificates),
	}

	return resp, nil
}
