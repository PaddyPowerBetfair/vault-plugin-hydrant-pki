package pki

import (
	"context"
	"fmt"
	"strings"
	"vault-plugin-hydrant-pki/pkg/hydrant"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

var _ logical.Factory = Factory

// Factory configures and returns Mock backends
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b, err := newBackend(conf, nil)
	if err != nil {
		return nil, err
	}

	if conf == nil {
		return nil, fmt.Errorf("configuration passed into backend is nil")
	}

	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	return b, nil
}

type hydrantConstructor func(*hydrant.ClientConfig) (hydrant.Client, error)

// Backend returns a new Backend framework struct
func newBackend(conf *logical.BackendConfig, clientConstructor hydrantConstructor) (*Backend, error) {
	if clientConstructor == nil {
		clientConstructor = hydrant.New
	}
	b := &Backend{
		clientConstructor: clientConstructor,
	}
	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(hydrantHelp),
		BackendType: logical.TypeLogical,
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"config/authn",
			},
		},
	}

	b.Backend.Paths = append(b.Backend.Paths, b.paths()...)
	return b, nil
}

const hydrantHelp = `
HydrantID plugin enables you to Issue and Manage certificates using your HydrantID ACM instance.
`

// Backend wraps the Backend framework and adds a map for storing key value pairs
type Backend struct {
	*framework.Backend

	// cachedHydrantClient should not be used directly, please call the getter method getAtlasClient
	cachedHydrantClient hydrant.Client
	clientConstructor   hydrantConstructor
	reloadConfig        bool
}

// setSystemValue persists a value in the provided vault logical storage Backend using the system prefix.
func (b *Backend) setSystemValue(ctx context.Context, storage logical.Storage, key string, value []byte) error {
	return storage.Put(ctx, &logical.StorageEntry{
		Key:      storageSystemPrefix + key,
		Value:    value,
		SealWrap: true,
	})
}

// getSystemValue gets the vault stored state under the system prefix using the provided logical storage.
func (b *Backend) getSystemValue(ctx context.Context, storage logical.Storage, key string) ([]byte, error) {
	sysVal, err := storage.Get(ctx, storageSystemPrefix+key)
	if err != nil {
		return nil, err
	}
	if sysVal == nil {
		return nil, fmt.Errorf("system value Not Found '%s'", key)
	}
	return sysVal.Value, nil
}

// GetHydrantClient gets the cached hydrant client or will lazily generate one based on stored parameters.
func (b *Backend) GetHydrantClient(ctx context.Context, storage logical.Storage) (hydrant.Client, error) {
	// Check cached version
	if b.cachedHydrantClient != nil && !b.reloadConfig {
		return b.cachedHydrantClient, nil
	}

	// Lazy construct using stored parameters
	id, err := b.getSystemValue(ctx, storage, storageHydrantID)
	if err != nil {
		return nil, err
	}

	key, err := b.getSystemValue(ctx, storage, storageHydrantKey)
	if err != nil {
		return nil, err
	}

	url, err := b.getSystemValue(ctx, storage, storageHydrantURL)
	if err != nil {
		return nil, err
	}
	if url == nil {
		url = []byte("https://acm-stage.hydrantid.com/api/v2")
	}

	policyId, err := b.getSystemValue(ctx, storage, storagePolicyId)
	if err != nil {
		return nil, err
	}

	// Assumption: Constructor will throw error if atlas is misconfigured.
	hydrantClient, err := b.clientConstructor(&hydrant.ClientConfig{
		HURL:     hydrant.String(string(url)),
		PolicyId: hydrant.String(string(policyId)),
		ID:       hydrant.String(string(id)),
		Key:      hydrant.String(string(key)),
	})
	if err != nil {
		return nil, err
	}

	// Make a call with the provided parameters to tie an error to the configuration if necessary.
	if err := hydrantClient.Login(b.Logger()); err != nil {
		return nil, err
	}

	// Set cached version to avoid future reconstruction
	b.cachedHydrantClient = hydrantClient
	return b.cachedHydrantClient, nil
}

func (b *Backend) paths() []*framework.Path {
	return []*framework.Path{
		//delete cert - revoke
		pathRevoke(b),
		//read policies/id
		pathFetchPolicy(b),
		//read policies
		pathFetchPolicies(b),
		//update - write config/authn
		pathConfigureAuthn(b),
		// read config
		pathGetConfiguration(b),
		//update - write issue
		pathIssue(b),
		//read cert/id pem with chain
		pathFetchCertificatePem(b),
		//read cert/id
		pathFetchCertificate(b),
		//read certh/id
		pathFetchCertificateHydrant(b),
		//read certsh
		pathFetchCertificatesHydrant(b),
		//read certsh
		pathFetchCertificates(b),
		//write renew/id
		pathRenew(b),
	}
}

const (
	// storageSystemPrefix is used to store things like module configuration
	storageSystemPrefix = "sys/"

	// Configuration value locations, stored under system prefix.
	storageHydrantID  = "hydrant/id"
	storageHydrantKey = "hydrant/key"
	storageHydrantURL = "hydrant/url"
	storagePolicyId   = "hydrant/policyId"
)
