# Vault Plugin Hydrant Pki

This is a PKI secrets engine plugin for [HashiCorp Vault](https://www.vaultproject.io/) that integrates [HydrantID](https://hydrantid.com/) as a CA provider.

## Usage
### Config

All commands can be run using the provided [Makefile](./Makefile). Using the Makefile will result in running the Vault server in `dev` mode. The `dev` server allows you to configure the plugin directory as a flag, and automatically registers plugin binaries in that directory. In production, plugin binaries must be manually registered.

This will build the plugin binary and start the Vault dev server:

```
# Build hydrant pki plugin and start Vault dev server with plugin automatically registered
$ make
```

Now open a new terminal window and run the following commands:

```
# Open a new terminal window and export Vault dev server http address
$ export VAULT_ADDR='http://127.0.0.1:8200'

# Login as root
$ make login

# Enable the Hydrant pki plugin
$ make enable

# Configure the Hydrant pki plugin
$ make configure
```
or you could just run 
```
# Login/Enable/Configure the Hydrant pki plugin
$ make config
```

### Plugin commands

```
# Issue a certificate with the HydrantID pki secrets engine
$ vault write pki/issue cn="some.domain.endpoint"

# Read a certificate with the HydrantID pki secrets engine stored in Vault
$ vault read pki/cert/id-of-certificate

# Read all certificate ids with the HydrantID pki secrets engine stored in Vault
$ vault read pki/certs

# Read a certificate with the HydrantID pki secrets engine stored in Hydrant
$ vault read pki/certh/id-of-certificate

# Read all certificate ids with the HydrantID pki secrets engine stored in Hydrant
$ vault read pki/certsh

# Revoke a certificate with the HydrantID pki secrets engine
$ vault delete pki/cert/id-of-certificate reason=1

# Read a policy with the HydrantID pki secrets engine from Hydrant
$ vault read pki/policy/id-of-policy

# Read all policies with the HydrantID pki secrets engine from Hydrant
$ vault read pki/policies

# Write the HydrantID pki secrets engine configuration (id, key and endpoint)
$ vault write pki/config/authn id=$HYDRANT_ID key=$HYDRANT_KEY url="https://acm-stage.hydrantid.com/api/v2" policyId=$HYDRANT_POLICY_ID

# Read the current HydrantID pki secrets engine configuration
$ vault read pki/config

# Renew a certificate with the HydrantID pki secrets engine - requires the policy to allow renewal with existing csr
$ vault write pki/renew/id-of-certificate
```
#### Help
```
# Help for any path
$ vault path-help pki/issue
Request:        issue
Matching Route: ^issue$

Request a certificate with the provided details.

## PARAMETERS

    cn (string)

        Specifies the CN for the certificate.

    ttl (int)

        Specifies the TTL for the certificate (in months). Defaults to 12 months if not specified.

## DESCRIPTION

This path allows requesting a certificate to be issued. The certificate will only be issued if the
requested details are allowed by the hydrant policy.
This path returns a certificate and a private key.
```
