package hydrant

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"github.com/hiyosi/hawk"
	"time"
)

func String(s string) *string {
	return &s
}

func DerefString(s *string) string {
	if s != nil {
		return *s
	}

	return ""
}

func GetHawkClient(id *string, key *string) *hawk.Client {
	hawkClient := hawk.NewClient(
		&hawk.Credential{
			ID:  DerefString(id),
			Key: DerefString(key),
			Alg: hawk.SHA256,
		},
		&hawk.Option{
			TimeStamp: time.Now().Unix(),
			Nonce:     "3hOHpR",
			Ext:       "some-app-data",
		},
	)
	return hawkClient
}

func generateCSR(cn string) (string, string, string) {
	var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
	keyBytes, _ := rsa.GenerateKey(rand.Reader, 4096)

	//todo replace with service account email
	emailAddress := "someemail@someemail.com"
	subj := pkix.Name{
		CommonName:         cn,
		Country:            []string{"IE"},
		Province:           []string{"Leinster"},
		Locality:           []string{"Dublin"},
		Organization:       []string{"Paddy Power Betfair Limited"},
		OrganizationalUnit: []string{"IT"},
		ExtraNames: []pkix.AttributeTypeAndValue{
			{
				Type: oidEmailAddress,
				Value: asn1.RawValue{
					Tag:   asn1.TagIA5String,
					Bytes: []byte(emailAddress),
				},
			},
		},
	}

	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, keyBytes)
	privateKey := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(keyBytes),
		},
	)
	publicKey := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: x509.MarshalPKCS1PublicKey(&keyBytes.PublicKey),
		},
	)
	var csr = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	return string(privateKey), string(publicKey), string(csr)
}
