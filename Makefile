GOARCH = amd64

UNAME = $(shell uname -s)

ifndef OS
	ifeq ($(UNAME), Linux)
		OS = linux
	else ifeq ($(UNAME), Darwin)
		OS = darwin
	endif
endif

.DEFAULT_GOAL := all

all: fmt clean build start
config: login enable configure
testing: test

build:
	GOOS=$(OS) GOARCH="$(GOARCH)" go build -o vault/plugins/vault-plugin-hydrant-pki cmd/vault-plugin-hydrant-pki/main.go

test:
	GOOS=$(OS) GOARCH="$(GOARCH)" go test

start:
	vault server -dev -dev-root-token-id=root -dev-plugin-dir=./vault/plugins

login:
	export VAULT_ADDR="http://127.0.0.1:8200"; vault login root

enable:
	export VAULT_ADDR="http://127.0.0.1:8200"; vault secrets enable -path=pki vault-plugin-hydrant-pki

configure:
	export VAULT_ADDR="http://127.0.0.1:8200"; vault write pki/config/authn id=$$HYDRANT_ID key=$$HYDRANT_KEY url="https://acm-stage.hydrantid.com/api/v2" policyId=$$HYDRANT_POLICY_ID

clean:
	rm -f ./vault/plugins/vault-plugin-hydrant-pki

fmt:
	go fmt $$(go list ./...)

.PHONY: build clean fmt start enable
