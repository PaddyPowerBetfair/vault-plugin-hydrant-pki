package pki

import (
	"context"
	"github.com/fatih/structs"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathFetchPolicy(b *Backend) *framework.Path {
	return &framework.Path{
		Pattern: `policy/(?P<id>([a-fA-F0-9]+-)+[a-fA-F0-9]+)`,
		Fields: map[string]*framework.FieldSchema{
			"id": {
				Type:        framework.TypeString,
				Description: `Policy id`,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathFetchPolicy,
				Summary:  "Fetch policy from Hydrant.",
			},
		},

		HelpSynopsis:    pathFetchPolicyHelpSyn,
		HelpDescription: pathFetchPolicyHelpDesc,
	}
}

const pathFetchPolicyHelpSyn = `
Fetch policy from Hydrant.
`

const pathFetchPolicyHelpDesc = `
This path allows the fetching of a policy with all of its fields from Hydrant. 
This is a way to check if a requested certificate will be issued/signed = if it corresponds to the policy requirements.
`

func pathFetchPolicies(b *Backend) *framework.Path {
	return &framework.Path{
		Pattern: `policies`,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathFetchPolicies,
				Summary:  "Fetch policies from Hydrant.",
			},
		},

		HelpSynopsis:    pathFetchPoliciesHelpSyn,
		HelpDescription: pathFetchPoliciesHelpDesc,
	}
}

const pathFetchPoliciesHelpSyn = `
Fetch policies from Hydrant.
`

const pathFetchPoliciesHelpDesc = `
Fetch policies from Hydrant. This path will return an array of policies that are stored in Hydrant.
`

func (b *Backend) pathFetchPolicy(ctx context.Context, request *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	id := data.Get("id").(string)
	b.Backend.Logger().Info("pathFetchPolicy id: " + id)

	hydrantClient, err := b.GetHydrantClient(ctx, request.Storage)
	if err != nil {
		b.Backend.Logger().Error(err.Error())
		return nil, err
	}
	policy, err := hydrantClient.GetPolicy(b.Logger(), id)
	if err != nil {
		return nil, err
	}

	resp := &logical.Response{
		Data: structs.Map(policy),
	}

	return resp, nil
}

func (b *Backend) pathFetchPolicies(ctx context.Context, request *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.Backend.Logger().Info("pathFetchPolicies enter!")

	hydrantClient, err := b.GetHydrantClient(ctx, request.Storage)
	if err != nil {
		b.Backend.Logger().Error(err.Error())
		return nil, err
	}
	policies, err := hydrantClient.GetPolicies(b.Logger())
	if err != nil {
		return nil, err
	}
	rawData := map[string]interface{}{
		"policies": policies,
	}
	resp := &logical.Response{
		Data: rawData,
	}

	return resp, nil
}
