package pki

import (
	"context"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/errutil"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	// configId is the plugin storage path component for the Hydrant id, used under the system prefix
	configId = "id"
	// configKey is the plugin storage path component for the Hydrant key, used under the system prefix
	configKey = "key"
	// configHURL is the plugin storage path component for the Hydrant URL, used under the system prefix
	configHURL = "url"
	// configPolicyId is the plugin storage path component for the Hydrant Policy ID, used under the system prefix
	configPolicyId = "policyId"
)

func pathGetConfiguration(b *Backend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.handleConfigRead,
				Summary:  "Read configuration for hydrant-vault plugin.",
			},
		},

		HelpSynopsis:    `Read configuration for the Hydrant backend authentication information.`,
		HelpDescription: `Reads the configuration for the Hydrant backend authentication information currently stored in Vault. Gets the ID, KEY and URL for authenticating with Hydrant.`,
	}
}

func (b *Backend) handleConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if req.ClientToken == "" {
		b.Logger().Error("error client token")
		return nil, errutil.UserError{Err: "client token must not be empty"}
	}

	b.Backend.Logger().Info("handleConfigRead enter!")

	id, err := b.getSystemValue(ctx, req.Storage, storageHydrantID)
	if err != nil {
		return nil, errutil.InternalError{Err: "Failed to retrieve id: " + err.Error()}
	}
	key, err := b.getSystemValue(ctx, req.Storage, storageHydrantKey)
	if err != nil {
		return nil, errutil.InternalError{Err: "Failed to retrieve key: " + err.Error()}
	}
	url, err := b.getSystemValue(ctx, req.Storage, storageHydrantURL)
	if err != nil {
		return nil, errutil.InternalError{Err: "Failed to retrieve url: " + err.Error()}
	}
	policyId, err := b.getSystemValue(ctx, req.Storage, storagePolicyId)
	if err != nil {
		return nil, errutil.InternalError{Err: "Failed to retrieve policyId: " + err.Error()}
	}

	rawData := map[string]interface{}{
		"id":       string(id),
		"key":      string(key),
		"url":      string(url),
		"policyId": string(policyId),
	}

	resp := &logical.Response{
		Data: rawData,
	}

	return resp, nil
}

func pathConfigureAuthn(b *Backend) *framework.Path {
	return &framework.Path{
		Pattern: "config/authn",
		Fields: map[string]*framework.FieldSchema{
			configId: {
				Type:        framework.TypeString,
				Description: `The Hydrant ID you wish to use.`,
			},
			configKey: {
				Type:        framework.TypeString,
				Description: `The Hydrant Key you wish to use.`,
			},
			configHURL: {
				Type:        framework.TypeString,
				Description: `The Hydrant URL you wish to use.`,
			},
			configPolicyId: {
				Type:        framework.TypeString,
				Description: `The Hydrant Policy ID you wish to use.`,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleConfigWrite,
				Summary:  "Configure hydrant-vault plugin.",
			},
		},

		HelpSynopsis:    `Configures the Hydrant backend authentication information.`,
		HelpDescription: `Configures the Hydrant backend authentication information. Sets the ID, KEY, URL and POLICY ID for authenticating with Hydrant.`,
	}
}

func (b *Backend) handleConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if req.ClientToken == "" {
		b.Logger().Error("error client token")
		return nil, errutil.UserError{Err: "client token must not be empty"}
	}

	// Check to make sure that kv pairs provided
	if len(req.Data) == 0 {
		b.Logger().Error("error no data provided")
		return nil, errutil.UserError{Err: "data must be provided to store in secret"}
	}

	id, ok := data.Get(configId).(string)
	if ok && id != "" {
		err := b.setSystemValue(ctx, req.Storage, storageHydrantID, []byte(id))
		if err != nil {
			return nil, errutil.InternalError{Err: "Failed to Save id: " + err.Error()}
		}
		b.reloadConfig = true
	}

	key, ok := data.Get(configKey).(string)
	if ok && key != "" {
		err := b.setSystemValue(ctx, req.Storage, storageHydrantKey, []byte(key))

		if err != nil {
			return nil, errutil.InternalError{Err: "Failed to Save key: " + err.Error()}
		}
		b.reloadConfig = true
	}

	url, ok := data.Get(configHURL).(string)
	if ok && url != "" {
		err := b.setSystemValue(ctx, req.Storage, storageHydrantURL, []byte(url))

		if err != nil {
			return nil, errutil.InternalError{Err: "Failed to Save url: " + err.Error()}
		}
		b.reloadConfig = true
	}

	policyId, ok := data.Get(configPolicyId).(string)
	if ok && policyId != "" {
		err := b.setSystemValue(ctx, req.Storage, storagePolicyId, []byte(policyId))

		if err != nil {
			return nil, errutil.InternalError{Err: "Failed to Save policy id: " + err.Error()}
		}
		b.reloadConfig = true
	}

	//client, err := b.GetHydrantClient(ctx, req.Storage)
	//if err != nil {
	//	return nil, errutil.InternalError{Err: "hydrant client retrieval: " + err.Error()}
	//}

	// Make a request to test the connection
	//_, err = client.GetConfig(ctx)
	//if err != nil {
	//	return nil, errutil.InternalError{Err: "atlas test request failed: " + err.Error()}
	//}

	return nil, nil
}
