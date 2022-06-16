package hydrant

import (
	"fmt"
	"github.com/hashicorp/go-hclog"
)

type MockClient struct {
	OutError              error
	OutCert               *Certificate
	OutRevocationResponse *RevocationResponse
	OutPol                *Policy
	OutRenewResponse      *RenewResponse
	OutCertList           []string
	OutPols               []Policies
	OutCerts              *Certificates
	OutCertPem            string
}

var (
	MockCert1 = &Certificate{
		Id: "123-321",
		PublicKey: `
-----BEGIN CERTIFICATE-----
MIIEcjCCA1qgAwIBAgIQAb4ElB1WWfbjZRykITZ+GDANBgkqhkiG9w0BAQsFADBS
MQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEoMCYGA1UE
AxMfR2xvYmFsU2lnbiBOb24tUHVibGljIEhWQ0EgRGVtbzAeFw0yMDExMjQwODM3
NTFaFw0yMDEyMjYwODM4MjFaMEExCzAJBgNVBAYTAlVTMRswGQYDVQQKDBJHbG9i
YWxTaWduIEFFRyBEZXYxFTATBgNVBAMMDGV4YW1wbGVfcm9sZTCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAMWU8jxBwPQquEM1VcFh1OUakvpD2q5WsJs3
9AAgI2ctksZvzw32AZNBto63noiOWQTYts+9SPNgbneaUviHwjdaJ2AOAO6yl5z7
45y12254okCLU96m8JAHFsrN5yFyV45GKpmWAWmD8iUJRgTOSWY9u2SdNWJkxmTI
PVrNPLqTPK+LuO5x+HGhQIy78Tgxoz8JXN1YO9sRoPOAjLCeTFkN0iCF+8lCfSDV
biE7iK0OSYEcmeSWV5Q/yUIxc4KPGB4snUHZLUPwJwx8+58yCdb9Q6O6Bn6zqp3l
6jRdPYD7VFHdebVLBnx9hDOtZ2RKOBTOzLLQXPcU/8gBJA7Yfg0CAwEAAaOCAVMw
ggFPMA4GA1UdDwEB/wQEAwIDqDATBgNVHSUEDDAKBggrBgEFBQcDAjAdBgNVHQ4E
FgQUhVL3S4+eVDv9rtOMlqpQM8YSHigwCQYDVR0TBAIwADCBlgYIKwYBBQUHAQEE
gYkwgYYwPAYIKwYBBQUHMAGGMGh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2Nh
L2dzbnBodmNhZGVtb3NoYTJnMzBGBggrBgEFBQcwAoY6aHR0cDovL3NlY3VyZS5n
bG9iYWxzaWduLmNvbS9jYWNlcnQvZ3NucGh2Y2FkZW1vc2hhMmczLmNydDAfBgNV
HSMEGDAWgBRnSwfpCfHxezLMvYUcTicNzqHMbDBEBgNVHR8EPTA7MDmgN6A1hjNo
dHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL2NhL2dzbnBodmNhZGVtb3NoYTJnMy5j
cmwwDQYJKoZIhvcNAQELBQADggEBAJC92kS4QJyubFMi54GwmY0OVOj5VSzp8hb0
idct117ms63oNCU/WYDI1rC/wUvrI8PIE/dLsD3MYGKCbl2w2ZAzY6FQI646PC3J
JC7TEIPnbpcf8epfC3aglOj26IERgagVoWo137kzEsKN7bNy2zrNiTu4bZOm1zFq
LP0k4EQ6r1uCLVLj7BOkSQ8WZ552usv26eTYqppl7yL0A+nrq8CL3KFVwbfsMz2C
xV3jSxHKuZ8+oEpD+R8rPlH2WSgqPxu0TIowGXGoKwcF6/5qJBj6R5ZKC/y5E9Qm
SIWufet+dT+AvaVtKLDu1DewwXiK177L2iv6U7cc1mOV4xL91Qc=
-----END CERTIFICATE-----`,
	}

	MockCert2 = &Certificate{
		Id: "321-123",
		PublicKey: `
-----BEGIN CERTIFICATE-----
MIIEcjCCA1qgAwIBAgIQAb4ElB1WWfbjZRykITZ+GDANBgkqhkiG9w0BAQsFADBS
MQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEoMCYGA1UE
AxMfR2xvYmFsU2lnbiBOb24tUHVibGljIEhWQ0EgRGVtbzAeFw0yMDExMjQwODM3
NTFaFw0yMDEyMjYwODM4MjFaMEExCzAJBgNVBAYTAlVTMRswGQYDVQQKDBJHbG9i
YWxTaWduIEFFRyBEZXYxFTATBgNVBAMMDGV4YW1wbGVfcm9sZTCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAMWU8jxBwPQquEM1VcFh1OUakvpD2q5WsJs3
9AAgI2ctksZvzw32AZNBto63noiOWQTYts+9SPNgbneaUviHwjdaJ2AOAO6yl5z7
45y12254okCLU96m8JAHFsrN5yFyV45GKpmWAWmD8iUJRgTOSWY9u2SdNWJkxmTI
PVrNPLqTPK+LuO5x+HGhQIy78Tgxoz8JXN1YO9sRoPOAjLCeTFkN0iCF+8lCfSDV
biE7iK0OSYEcmeSWV5Q/yUIxc4KPGB4snUHZLUPwJwx8+58yCdb9Q6O6Bn6zqp3l
6jRdPYD7VFHdebVLBnx9hDOtZ2RKOBTOzLLQXPcU/8gBJA7Yfg0CAwEAAaOCAVMw
ggFPMA4GA1UdDwEB/wQEAwIDqDATBgNVHSUEDDAKBggrBgEFBQcDAjAdBgNVHQ4E
FgQUhVL3S4+eVDv9rtOMlqpQM8YSHigwCQYDVR0TBAIwADCBlgYIKwYBBQUHAQEE
gYkwgYYwPAYIKwYBBQUHMAGGMGh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2Nh
L2dzbnBodmNhZGVtb3NoYTJnMzBGBggrBgEFBQcwAoY6aHR0cDovL3NlY3VyZS5n
bG9iYWxzaWduLmNvbS9jYWNlcnQvZ3NucGh2Y2FkZW1vc2hhMmczLmNydDAfBgNV
HSMEGDAWgBRnSwfpCfHxezLMvYUcTicNzqHMbDBEBgNVHR8EPTA7MDmgN6A1hjNo
dHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL2NhL2dzbnBodmNhZGVtb3NoYTJnMy5j
cmwwDQYJKoZIhvcNAQELBQADggEBAJC92kS4QJyubFMi54GwmY0OVOj5VSzp8hb0
idct117ms63oNCU/WYDI1rC/wUvrI8PIE/dLsD3MYGKCbl2w2ZAzY6FQI646PC3J
JC7TEIPnbpcf8epfC3aglOj26IERgagVoWo137kzEsKN7bNy2zrNiTu4bZOm1zFq
LP0k4EQ6r1uCLVLj7BOkSQ8WZ552usv26eTYqppl7yL0A+nrq8CL3KFVwbfsMz2C
xV3jSxHKuZ8+oEpD+R8rPlH2WSgqPxu0TIowGXGoKwcF6/5qJBj6R5ZKC/y5E9Qm
SIWufet+dT+AvaVtKLDu1DewwXiK177L2iv6U7cc1mOV4xL91Qc=
-----END CERTIFICATE-----`,
	}

	MockCert3 = &Certificate{
		CommonName: "",
		PrivateKey: "",
		PublicKey:  "",
		Id:         "123",
		DL:         "",
	}

	MockCert4 = &Certificate{
		Id:         "656462c5-a942-43bb-95bc-38a9adeb40b6",
		CommonName: "ade.dev.endpoint",
		PublicKey: `
-----BEGIN CERTIFICATE-----
MIIHKDCCBRCgAwIBAgIUQGNYy0htbuudH9kMdiyGSZqRrAYwDQYJKoZIhvcNAQEL
BQAwczELMAkGA1UEBhMCSUUxMzAxBgNVBAoMKlBhZGR5IFBvd2VyIEJldGZhaXIg
UHVibGljIExpbWl0ZWQgQ29tcGFueTEvMC0GA1UEAwwmUGFkZHkgUG93ZXIgQmV0
ZmFpciBEZXZlbG9wbWVudCBJQ0EgMUEwHhcNMjIwNDA1MTM1MTU1WhcNMjMwNDA1
MTM1MTU1WjCBgTELMAkGA1UEBhMCSUUxETAPBgNVBAgMCExlaW5zdGVyMQ8wDQYD
VQQHDAZEdWJsaW4xMzAxBgNVBAoMKlBhZGR5IFBvd2VyIEJldGZhaXIgUHVibGlj
IExpbWl0ZWQgQ29tcGFueTEZMBcGA1UEAwwQYWRlLmRldi5lbmRwb2ludDCCAiIw
DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANVApIBykceMIC4VsDclQlODsmE5
nJAADlVK4Xvf7AHNlg7nB2McZJPIVoXwoYvUPCpsz9pBQdHZmYFTaA8YiCESynRS
9wbQTmHAgclBXMArYQwxw3xKGbT4t5yY/K4NtHWN3K863G++6+dwyahILi5W79Qa
PvSUHZtBJjTMf0lT3VuLdi8ekQxxVYYUvCeHOLwb2oGq7ogJJQXJxay+02XLQOWB
pPCgMEIBLLlHUPYExW1ctBmMH83m3KTTuqTPLn8Cd75+RMqAn2OLt6I+SgZ//1yg
Msof3tcFmiwdnvUl7DC3dTjwG1WKqeDFCPLwIbZPf5Kti+eOwoeFMA4vuDQER9IT
XheGjLe+4MZOh/X0ISKsYv1KAfDvGWlWm3g7MywYVcsCb4fkjkTIP9do0va9FyMv
7/evoN7L+I4GhRznxxhnssHH19SFKDUZ7LTsz5Zp8i2+5/LhS9sJWngegw3fZCfC
bElCMDr9MNngXzsbSNAt4qCZv8ZgehUYi9Pp8+9NV4kPoOz4o5KUS5b4QMNTHvPI
6EFHOYWdtSWGcyTy6Dfjuqf0IGVSa/gL1yXYfH9hKFzRYLb/4quby7HL2q1kaM7J
dbwZnfZVCHnhiVyERucnDHf7WiONoi9zM2c/Z9Z7hTOktT/i8fr4jvValnPDtIDJ
hOLZBVPNeKHNrZdLAgMBAAGjggGjMIIBnzAMBgNVHRMBAf8EAjAAMB8GA1UdIwQY
MBaAFD6zTUFnyZ5J22PbmbrtpketYDgwMIGTBggrBgEFBQcBAQSBhjCBgzBOBggr
BgEFBQcwAoZCaHR0cDovL2NybC1kZXYucGFkZHlwb3dlcmJldGZhaXIuY29tL1Bh
ZGR5UG93ZXJCZXRmYWlyRGV2SUNBMUEuY3J0MDEGCCsGAQUFBzABhiVodHRwOi8v
b2NzcC1kZXYucGFkZHlwb3dlcmJldGZhaXIuY29tMBsGA1UdEQQUMBKCEGFkZS5k
ZXYuZW5kcG9pbnQwGAYDVR0gBBEwDzANBgsrBgEEAYKWaYdnATAdBgNVHSUEFjAU
BggrBgEFBQcDAgYIKwYBBQUHAwEwUwYDVR0fBEwwSjBIoEagRIZCaHR0cDovL2Ny
bC1kZXYucGFkZHlwb3dlcmJldGZhaXIuY29tL1BhZGR5UG93ZXJCZXRmYWlyRGV2
SUNBMUEuY3JsMB0GA1UdDgQWBBQXvJSyzcBN5kOFr444flzoC5TFtjAOBgNVHQ8B
Af8EBAMCBaAwDQYJKoZIhvcNAQELBQADggIBAAJLDPoNbmuzvJrGKU6lCd8i9BSX
nEVgCN7AbpDmvJlmojo9Q11IeV7L2+AMb1JdxDT9eZJFvDV8/Pbs5VYVsDwx7y39
vCEGxIwBD6i/nK9kF8s1Rt9eF+AZH0Q97PXbSxj44FBKX+ErPPJPvgmqKmWYM+P2
oq9h95nYVwnrBTIT5yWmbAoZnMoFSFjY0B0XS0vu+fFPYPQfZcOnCDy8fBKimnh8
8axKJrE0Ius6Z6vbJ1KRkKkoV7L+5N7NzEzB5MQZ3evUTNLtNEdWfyRqgFWvLK3D
5p5cN9/lVIbvCbFIPnZoKE0s8bQ6VmxY8hniyk3qeicR9fxyouTnFKA3V3GmO832
IDLg0IbVYaabjmqjUA4nEAciBJrX+HDro91fmjPzgxqYfCiy9vZS0jWEkFn8J0ks
2MWWy6H3Jl585XzXAYROEerD42Jmj4qoDCzNxa/g8Aw8lnJm/M6XssTOMOmM/gQ8
0gj4mV8uij0HEX/SVSWmQguTglBRjBy3gwuHRioWQxh9LQzHwbtWpvsFgDFLMb+e
Oe9SN+hu2SASg5BVUd+rdxb+0zOZZFOHnvk5sVZWJnAMpkdUdb4d0v/PfC40qEHq
nzIijVnuXd15JOaijk7PEjYHDLcK+tlqvcZQDmEzjxfprL/cVPkzh3qDBhd9IEhV
J2jYSm44ismYNj+g
-----END CERTIFICATE-----`,
	}

	MockPolicy1 = &Policy{
		Id:   "123-321",
		Name: "MockPol1",
	}

	MockPolicy2 = &Policy{
		Id:   "123-321",
		Name: "MockPol1",
	}

	MockPolicies = &Policies{
		ID:   "231-234",
		Name: "pol1",
	}

	MockCerts = &Certificates{
		Count: 5,
	}

	certPem = string("ade.test")

	MockRevocationResponse = &RevocationResponse{
		RevocationStatus: "Revoked",
	}

	MockRenewResp = &RenewResponse{
		Id:               "",
		IssuanceStatus:   "renew",
		CertificateId:    "1111",
		RevocationStatus: "revoked",
	}
)

// GetPolicies fetch policies from HydrantID.
func (c *MockClient) GetPolicies(logger hclog.Logger) ([]Policies, error) {
	if c.OutError != nil {
		return nil, c.OutError
	}
	return c.OutPols, nil
}

// GetPolicy fetch policy by id from HydrantID.
func (c *MockClient) GetPolicy(logger hclog.Logger, id string) (*Policy, error) {
	if c.OutError != nil {
		return nil, c.OutError
	}
	if c.OutPol == nil {
		c.OutPol = MockPolicy1
	}
	return c.OutPol, nil
}

// IssueCertificate will that the provided CSR and Parameters to request issuance of a certificate from the HydrantID Instance.
func (c *MockClient) IssueCertificate(logger hclog.Logger, req *IssueCertRequest) (*Certificate, error) {
	if c.OutError != nil {
		return nil, c.OutError
	}
	if c.OutCert == nil {
		c.OutCert = MockCert1
	} else {
		privateKey, publicKey, _ := generateCSR(req.CN)
		MockCert3.CommonName = req.CN
		MockCert3.PrivateKey = privateKey
		MockCert3.PublicKey = publicKey
		c.OutCert = MockCert3
	}
	return c.OutCert, nil
}

func (c *MockClient) GetCertPem(logger hclog.Logger, id string) (string, error) {
	if c.OutCert == nil {
		c.OutCertPem = certPem
	}
	return c.OutCertPem, nil

}

// GetCert gets the certificate for the provided id.
func (c *MockClient) GetCert(logger hclog.Logger, id string) (*Certificate, error) {
	if c.OutError != nil {
		return nil, c.OutError
	}
	return c.OutCert, nil
}

// GetCerts gets all the certificates.
func (c *MockClient) GetCerts(logger hclog.Logger, filter *CertificatesFilter) (*Certificates, error) {
	if c.OutError != nil {
		return nil, c.OutError
	}
	if c.OutCerts == nil {
		c.OutCerts = MockCerts
	}
	return c.OutCerts, nil
}

// RevokeCert revokes the certificate with the provided id.
func (c *MockClient) RevokeCert(logger hclog.Logger, req *RevocationRequest) (*RevocationResponse, error) {
	if c.OutError != nil {
		return nil, c.OutError
	}
	if c.OutRevocationResponse == nil {
		c.OutRevocationResponse = MockRevocationResponse
	}
	return c.OutRevocationResponse, nil
}

// RenewCert renews the certificate (with the same CSR) with the provided id if the policy allows renewCanReuseCSR.
func (c *MockClient) RenewCert(logger hclog.Logger, id string) (*RenewResponse, error) {
	if c.OutError != nil {
		return nil, c.OutError
	}
	if c.OutRenewResponse != nil {
		c.OutRenewResponse = MockRenewResp
		c.OutRenewResponse.Id = id
	}
	return c.OutRenewResponse, nil
}

//GetCSRStatus get CSR status.
func (c *MockClient) GetCSRStatus(logger hclog.Logger, certRequestId string) (*CSRStatus, error) {
	fmt.Println("Not yet implemented!")
	panic("Not implemented!")
}

func (c *MockClient) Login(hclog.Logger) error {
	fmt.Println("Not yet implemented!")
	return nil
}
