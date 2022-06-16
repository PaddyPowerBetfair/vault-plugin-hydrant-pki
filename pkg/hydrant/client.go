package hydrant

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hashicorp/go-hclog"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Certificate is the API structured object returned by HydrantID
type Certificate struct {
	Id                 string   `json:"id"`
	Serial             string   `json:"serial"`
	CommonName         string   `json:"commonName"`
	CertRequestId      string   `json:"certRequestId"`
	SubjectDN          string   `json:"subjectDN"`
	IssuerDN           string   `json:"issuerDN"`
	NotBefore          string   `json:"notBefore"`
	NotAfter           string   `json:"notAfter"`
	SignatureAlgorithm string   `json:"signatureAlgorithm"`
	RevocationStatus   string   `json:"revocationStatus"`
	RevocationReason   int      `json:"revocationReason"`
	RevocationDate     string   `json:"revocationDate"`
	Pem                string   `json:"pem"`
	Imported           bool     `json:"imported"`
	CreatedAt          string   `json:"createdAt"`
	SANs               []string `json:"SANs"`
	Policy             struct {
		Id   string `json:"id"`
		Name string `json:"name"`
	} `json:"policy"`
	User struct {
		Id    string `json:"id"`
		Email string `json:"email"`
	} `json:"user"`
	Account struct {
		Id   string `json:"id"`
		Name string `json:"name"`
	} `json:"account"`
	Organization struct {
		Id   string `json:"id"`
		Name string `json:"name"`
	} `json:"organization"`
	ExpiryNotifications []string `json:"expiryNotifications"`
	PrivateKey          string   `json:"private_key"`
	PublicKey           string   `json:"public_key"`
	DL                  string   `json:"distribution_list"`
}

type Certificates struct {
	Count int `json:"count"`
	Items []struct {
		Id               string   `json:"id"`
		CommonName       string   `json:"commonName"`
		Serial           string   `json:"serial"`
		NotBefore        string   `json:"notBefore"`
		NotAfter         string   `json:"notAfter"`
		RevocationStatus string   `json:"revocationStatus"`
		SANs             []string `json:"SANs"`
		Policy           struct {
			Name string `json:"name"`
		} `json:"policy"`
	} `json:"items"`
}

type Policies struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	APIID   int    `json:"apiId"`
	Details struct {
		Validity struct {
			Days     []string `json:"days"`
			Months   []string `json:"months"`
			MaxValue struct {
				Days int `json:"days"`
			} `json:"maxValue"`
			Required     bool `json:"required"`
			Modifiable   bool `json:"modifiable"`
			DefaultValue struct {
				Days   int `json:"days"`
				Months int `json:"months"`
			} `json:"defaultValue"`
		} `json:"validity"`
		Validator    string `json:"validator"`
		DnComponents []struct {
			Tag            string `json:"tag"`
			Label          string `json:"label"`
			Required       bool   `json:"required"`
			Modifiable     bool   `json:"modifiable"`
			CopyAsFirstSAN bool   `json:"copyAsFirstSAN"`
		} `json:"dnComponents"`
		ExpiryEmails struct {
			Tag          string `json:"tag"`
			Label        string `json:"label"`
			Required     bool   `json:"required"`
			Modifiable   bool   `json:"modifiable"`
			DefaultValue string `json:"defaultValue"`
		} `json:"expiryEmails"`
		SubjectAltNames []struct {
			Tag        string `json:"tag"`
			Label      string `json:"label"`
			Required   bool   `json:"required"`
			Modifiable bool   `json:"modifiable"`
		} `json:"subjectAltNames"`
		ApprovalRequired bool `json:"approvalRequired"`
	} `json:"details"`
	Enabled struct {
		UI   bool `json:"ui"`
		Acme bool `json:"acme"`
		Rest bool `json:"rest"`
		Scep bool `json:"scep"`
	} `json:"enabled"`
	OrganizationID         string `json:"organizationId"`
	CertificateAuthorityID string `json:"certificateAuthorityId"`
}

type Policy struct {
	Id      string `json:"id"`
	Name    string `json:"name"`
	ApiId   int    `json:"apiId"`
	Details struct {
		Validity struct {
			Years      string `json:"years"`
			Months     string `json:"months"`
			Days       string `json:"days"`
			Required   bool   `json:"required"`
			Modifiable bool   `json:"modifiable"`
		} `json:"validity"`
		DnComponents []struct {
			Tag            string `json:"tag"`
			Label          string `json:"label"`
			Required       bool   `json:"required"`
			Modifiable     bool   `json:"modifiable"`
			DefaultValue   string `json:"defaultValue"`
			CopyAsFirstSAN bool   `json:"copyAsFirstSAN"`
		} `json:"dnComponents"`
		SubjectAltNames []struct {
			Tag          string `json:"tag"`
			Label        string `json:"label"`
			Required     bool   `json:"required"`
			Modifiable   bool   `json:"modifiable"`
			DefaultValue string `json:"defaultValue"`
		} `json:"subjectAltNames"`
		ApprovalRequired bool `json:"approvalRequired"`
		ExpiryEmails     struct {
			Tag          string `json:"tag"`
			Label        string `json:"label"`
			Required     bool   `json:"required"`
			Modifiable   bool   `json:"modifiable"`
			DefaultValue string `json:"defaultValue"`
		} `json:"expiryEmails"`
		CustomFields []struct {
			Tag          string `json:"tag"`
			Label        string `json:"label"`
			Required     bool   `json:"required"`
			Modifiable   bool   `json:"modifiable"`
			DefaultValue string `json:"defaultValue"`
		} `json:"customFields"`
		CustomExtensions []struct {
			Oid          string `json:"oid"`
			Label        string `json:"label"`
			Required     bool   `json:"required"`
			Modifiable   bool   `json:"modifiable"`
			DefaultValue string `json:"defaultValue"`
		} `json:"customExtensions"`
	} `json:"details"`
	Enabled struct {
		Ui   bool `json:"ui"`
		Rest bool `json:"rest"`
		Acme bool `json:"acme"`
		Scep bool `json:"scep"`
		Est  bool `json:"est"`
	} `json:"enabled"`
	OrganizationId         string `json:"organizationId"`
	CertificateAuthorityId string `json:"certificateAuthorityId"`
}

type CertificatesFilter struct {
	CommonName    string `json:"common_name"`
	Serial        string `json:"serial"`
	NotBefore     string `json:"not_before"`
	NotAfter      string `json:"not_after"`
	Expired       bool   `json:"expired"`
	CreatedSince  string `json:"created_since"`
	UpdatedSince  string `json:"updated_since"`
	Status        string `json:"status"`
	Owner         string `json:"owner"`
	Account       string `json:"account"`
	Organization  string `json:"organization"`
	Policy        string `json:"policy"`
	Fingerprint   string `json:"fingerprint"`
	Limit         int    `json:"limit"`
	Offset        int    `json:"offset"`
	SortType      string `json:"sort_type"`
	SortDirection string `json:"sort_direction"`
	Pem           bool   `json:"pem"`
	Span          int    `json:"span"`
}

type RevocationResponse struct {
	Id               string `json:"id"`
	RevocationStatus string `json:"revocationStatus"`
	RevocationReason int    `json:"revocationReason"`
	RevocationDate   string `json:"revocationDate"`
}

type RenewResponse struct {
	Id                    string `json:"id"`
	IssuanceStatus        string `json:"issuanceStatus"`
	IssuanceStatusDetails struct {
		AdditionalProp1 struct {
		} `json:"additionalProp1"`
		AdditionalProp2 struct {
		} `json:"additionalProp2"`
		AdditionalProp3 struct {
		} `json:"additionalProp3"`
	} `json:"issuanceStatusDetails"`
	CertificateId    string `json:"certificateId"`
	RevocationStatus string `json:"revocationStatus"`
}

type RevocationRequest struct {
	ID       string
	Reason   int    `json:"reason"`
	IssuerDN string `json:"issuerDN"`
}

// IssueCertRequest is the base structure for certificate requests
type IssueCertRequest struct {
	CN   string
	TTL  int
	SANS []string
	DL   string
}

type CSR struct {
	Id                    string `json:"id"`
	IssuanceStatus        string `json:"issuanceStatus"`
	IssuanceStatusDetails struct {
		AdditionalProp1 struct {
		} `json:"additionalProp1"`
		AdditionalProp2 struct {
		} `json:"additionalProp2"`
		AdditionalProp3 struct {
		} `json:"additionalProp3"`
	} `json:"issuanceStatusDetails"`
	CertificateId    string `json:"certificateId"`
	RevocationStatus string `json:"revocationStatus"`
}

type CSRStatus struct {
	Id                    string `json:"id"`
	IssuanceStatus        string `json:"issuanceStatus"`
	IssuanceStatusDetails struct {
		AdditionalProp1 struct {
		} `json:"additionalProp1"`
		AdditionalProp2 struct {
		} `json:"additionalProp2"`
		AdditionalProp3 struct {
		} `json:"additionalProp3"`
	} `json:"issuanceStatusDetails"`
	CertificateId    string `json:"certificateId"`
	RevocationStatus string `json:"revocationStatus"`
}

type DnComponents struct {
	CN string   `json:"CN"`
	OU []string `json:"OU"`
	O  string   `json:"O"`
	L  string   `json:"L"`
	ST string   `json:"ST"`
	C  string   `json:"C"`
	DC []string `json:"DC"`
}

type Validity struct {
	Years  int `json:"years"`
	Months int `json:"months"`
	Days   int `json:"days"`
}

type SANS struct {
	DNSNAME    []string `json:"DNSNAME"`
	IPADDRESS  []string `json:"IPADDRESS"`
	RFC822NAME []string `json:"RFC822NAME"`
	UPN        []string `json:"UPN"`
}

type CertificateRequest struct {
	Policy          string       `json:"policy"`
	Csr             string       `json:"csr"`
	Validity        Validity     `json:"validity"`
	DnComponents    DnComponents `json:"dnComponents"`
	SubjectAltNames SANS         `json:"subjectAltNames"`
	CustomFields    struct {
		AdditionalProp1 struct {
		} `json:"additionalProp1"`
		AdditionalProp2 struct {
		} `json:"additionalProp2"`
		AdditionalProp3 struct {
		} `json:"additionalProp3"`
	} `json:"customFields"`
	CustomExtensions struct {
		AdditionalProp1 struct {
		} `json:"additionalProp1"`
		AdditionalProp2 struct {
		} `json:"additionalProp2"`
		AdditionalProp3 struct {
		} `json:"additionalProp3"`
	} `json:"customExtensions"`
	Comment                     string   `json:"comment"`
	ExpiryEmails                []string `json:"expiryEmails"`
	ClearRemindersCertificateId string   `json:"clearRemindersCertificateId"`
	CN                          string   `json:"CN"`
}

// Client acts as an interface between the local process and HydrantID.
type Client interface {
	// GetPolicies fetch policies from HydrantID.
	GetPolicies(logger hclog.Logger) ([]Policies, error)

	// GetPolicy fetch policy by id from HydrantID.
	GetPolicy(logger hclog.Logger, id string) (*Policy, error)

	// IssueCertificate will that the provided CSR and Parameters to request issuance of a certificate from the HydrantID Instance.
	IssueCertificate(logger hclog.Logger, req *IssueCertRequest) (*Certificate, error)

	// GetCert gets the certificate for the provided id.
	GetCert(logger hclog.Logger, id string) (*Certificate, error)

	// GetCertPem gets the certificate pem including the CA chain for the provided id.
	GetCertPem(logger hclog.Logger, id string) (string, error)

	// GetCerts gets all the certificates.
	GetCerts(logger hclog.Logger, filter *CertificatesFilter) (*Certificates, error)

	// RevokeCert revokes the certificate with the provided id.
	RevokeCert(logger hclog.Logger, req *RevocationRequest) (*RevocationResponse, error)

	// RenewCert renews the certificate (with the same CSR) with the provided id if the policy allows renewCanReuseCSR.
	RenewCert(logger hclog.Logger, id string) (*RenewResponse, error)

	//GetCSRStatus get CSR status.
	GetCSRStatus(logger hclog.Logger, certRequestId string) (*CSRStatus, error)

	//Login get all HAWK Credentials associated with the current user
	Login(hclog.Logger) error
}

// ClientConfig represents configuration options available to the ATLAS client.
type ClientConfig struct {
	ID       *string
	Key      *string
	HURL     *string
	PolicyId *string
}

type client struct {
	clientConfig *ClientConfig
	http         *http.Client
}

func New(conf *ClientConfig) (Client, error) {
	if conf == nil {
		return nil, fmt.Errorf("HYDRANT: must provide client config")
	}

	if conf.ID == nil || *conf.ID == "" {
		return nil, fmt.Errorf("HYDRANT: must provide ID in config")
	}
	if conf.Key == nil || *conf.Key == "" {
		return nil, fmt.Errorf("HYDRANT: must provide KEY in config")
	}

	if conf.HURL == nil {
		return nil, fmt.Errorf("HYDRANT: must provide URL")
	}

	return &client{
		clientConfig: conf,
		http:         &http.Client{},
	}, nil
}

func (c client) GetCertPem(logger hclog.Logger, id string) (string, error) {
	// build request header
	hawkClient := GetHawkClient(c.clientConfig.ID, c.clientConfig.Key)
	header, err := hawkClient.Header("GET", DerefString(c.clientConfig.HURL)+"/certificates/"+id+"/pem?chain=true")
	if err != nil {
		logger.Error(err.Error())
		return "", err
	}
	req, _ := http.NewRequest("GET", DerefString(c.clientConfig.HURL)+"/certificates/"+id+"/pem?chain=true", nil)
	req.Header.Set("Authorization", header)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		logger.Error(err.Error())
		return "", err
	}
	defer resp.Body.Close()

	// authenticate server response.
	_, err = hawkClient.Authenticate(resp)
	if err != nil {
		logger.Error("Server Authentication Failure!")
	}

	buff, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.Error("GetCertPem failure!")
		logger.Error(err.Error())
	} else {
		logger.Info("GetCertPem success: " + string(buff))
	}
	return string(buff), nil
}

func (c client) GetCert(logger hclog.Logger, id string) (*Certificate, error) {
	// build request header
	hawkClient := GetHawkClient(c.clientConfig.ID, c.clientConfig.Key)
	header, err := hawkClient.Header("GET", DerefString(c.clientConfig.HURL)+"/certificates/"+id)
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}
	req, _ := http.NewRequest("GET", DerefString(c.clientConfig.HURL)+"/certificates/"+id, nil)
	req.Header.Set("Authorization", header)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}
	defer resp.Body.Close()

	// authenticate server response.
	_, err = hawkClient.Authenticate(resp)
	if err != nil {
		logger.Error("Server Authentication Failure!")
	}

	certificateResponse := new(Certificate)
	buff, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.Error("GetCert failure!")
		logger.Error(err.Error())
	}
	if err == nil {
		logger.Info("GetCert success: " + string(buff))
		_ = json.Unmarshal(buff, &certificateResponse)
	}
	return certificateResponse, nil
}

func (c client) GetCerts(logger hclog.Logger, filter *CertificatesFilter) (*Certificates, error) {
	payloadBuf := new(bytes.Buffer)
	if filter != nil {
		err := json.NewEncoder(payloadBuf).Encode(filter)
		if err != nil {
			logger.Error(err.Error())
			return nil, err
		}
	}
	// build request header
	hawkClient := GetHawkClient(c.clientConfig.ID, c.clientConfig.Key)
	header, err := hawkClient.Header("POST", DerefString(c.clientConfig.HURL)+"/certificates/")
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}
	req, _ := http.NewRequest("POST", DerefString(c.clientConfig.HURL)+"/certificates/", payloadBuf)
	req.Header.Set("Authorization", header)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}
	defer resp.Body.Close()

	// authenticate server response.
	_, err = hawkClient.Authenticate(resp)
	if err != nil {
		logger.Error("Server Authentication Failure!")
	}

	certificatesResponse := new(Certificates)
	buff, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.Error("GetCerts failure!")
		logger.Error(err.Error())
	}
	if err == nil {
		logger.Info("GetCerts success: " + string(buff))
		err = json.Unmarshal(buff, &certificatesResponse)
		if err == nil {
			logger.Info("No errors unmarshalling certificates!")
		} else {
			logger.Error("Errors unmarshalling certificates!")
		}
	}
	return certificatesResponse, nil
}

func (c client) RevokeCert(logger hclog.Logger, request *RevocationRequest) (*RevocationResponse, error) {
	payloadBuf := new(bytes.Buffer)
	err := json.NewEncoder(payloadBuf).Encode(request)
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}

	// build request header
	hawkClient := GetHawkClient(c.clientConfig.ID, c.clientConfig.Key)
	header, err := hawkClient.Header("PATCH", DerefString(c.clientConfig.HURL)+"/certificates/"+request.ID)
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}
	req, _ := http.NewRequest("PATCH", DerefString(c.clientConfig.HURL)+"/certificates/"+request.ID, payloadBuf)
	req.Header.Set("Authorization", header)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}
	defer resp.Body.Close()

	// authenticate server response.
	_, err = hawkClient.Authenticate(resp)
	if err != nil {
		logger.Error("Server Authentication Failure!")
	}

	revocationResponse := new(RevocationResponse)
	buff, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.Error("pathRevokeCert failure!")
		logger.Error(err.Error())
	}
	if err == nil {
		logger.Info("pathRevokeCert success: " + string(buff))
		_ = json.Unmarshal(buff, &revocationResponse)
	}
	return revocationResponse, nil
}

func (c client) IssueCertificate(logger hclog.Logger, req *IssueCertRequest) (*Certificate, error) {
	privateKey, publicKey, csr := generateCSR(req.CN)
	//todo is this configurable? from policy - to allow specifying days?
	var ttlYear int
	if req.TTL > 365 {
		ttlYear = 2
	} else {
		ttlYear = 1
	}
	body := &CertificateRequest{
		Policy: DerefString(c.clientConfig.PolicyId),
		Csr:    csr,
		Validity: Validity{
			Years:  ttlYear,
			Months: 0,
			Days:   0,
		},
		ExpiryEmails: []string{req.DL},
		SubjectAltNames: SANS{
			DNSNAME: req.SANS,
		},
		DnComponents: DnComponents{
			CN: req.CN,
		},
	}
	payloadBuf := new(bytes.Buffer)
	err := json.NewEncoder(payloadBuf).Encode(body)
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}
	// build request header
	hawkClient := GetHawkClient(c.clientConfig.ID, c.clientConfig.Key)
	header, err := hawkClient.Header("POST", DerefString(c.clientConfig.HURL)+"/csr")
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}
	request, _ := http.NewRequest("POST", DerefString(c.clientConfig.HURL)+"/csr", payloadBuf)
	request.Header.Set("Authorization", header)
	request.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(request)
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}
	defer resp.Body.Close()

	// authenticate server response.
	_, err = hawkClient.Authenticate(resp)
	if err != nil {
		logger.Error("Server Authentication Failure")
	}

	var csrResponse = new(CSR)
	var csrStatus = new(CSRStatus)
	var cert = new(Certificate)
	buff, err := ioutil.ReadAll(resp.Body)
	if err == nil {
		logger.Info(string(buff))
		if strings.Contains(string(buff), "error") {
			return nil, errors.New(string(buff))
		}
		_ = json.Unmarshal(buff, &csrResponse)

		issuedSuccessfully := false
		for _, i := range []int{1, 2, 3} {
			csrStatus, _ = c.GetCSRStatus(logger, csrResponse.Id)
			if csrStatus.IssuanceStatus != "ISSUED" {
				logger.Info("status check: " + strconv.Itoa(i))
				time.Sleep(1 * time.Second)
			} else {
				logger.Info("DONE ISSUED!")
				issuedSuccessfully = true
				cert, _ = c.GetCert(logger, csrStatus.CertificateId)
				break
			}
		}
		if !issuedSuccessfully {
			return nil, errors.New("error csr status not issued")
		}
	} else {
		return nil, errors.New("error deserializing csr response")
	}
	cert.PrivateKey = privateKey
	cert.PublicKey = publicKey
	cert.DL = req.DL
	return cert, nil
}

func (c client) GetCSRStatus(logger hclog.Logger, certRequestId string) (*CSRStatus, error) {
	// build request header
	hawkClient := GetHawkClient(c.clientConfig.ID, c.clientConfig.Key)
	header, err := hawkClient.Header("GET", DerefString(c.clientConfig.HURL)+"/csr/"+certRequestId+"/status")
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}

	req, _ := http.NewRequest("GET", DerefString(c.clientConfig.HURL)+"/csr/"+certRequestId+"/status", nil)
	req.Header.Set("Authorization", header)

	resp, err := c.http.Do(req)
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}
	defer resp.Body.Close()

	// authenticate server response.
	_, err = hawkClient.Authenticate(resp)
	if err != nil {
		logger.Error("Server Authentication Failure")
	}

	buff, err := ioutil.ReadAll(resp.Body)
	if err == nil {
		logger.Info("status response: " + string(buff))
		var csrResponse = new(CSRStatus)
		_ = json.Unmarshal(buff, &csrResponse)
		return csrResponse, nil
	}
	return nil, err
}

func (c client) Login(logger hclog.Logger) error {
	// build request header
	hawkClient := GetHawkClient(c.clientConfig.ID, c.clientConfig.Key)
	header, err := hawkClient.Header("GET", DerefString(c.clientConfig.HURL)+"/hawk/")
	if err != nil {
		logger.Error(err.Error())
		return err
	}

	req, _ := http.NewRequest("GET", DerefString(c.clientConfig.HURL)+"/hawk/", nil)
	req.Header.Set("Authorization", header)

	resp, err := c.http.Do(req)
	if err != nil {
		logger.Error(err.Error())
		return err
	}
	defer resp.Body.Close()

	// authenticate server response.
	_, err = hawkClient.Authenticate(resp)
	if err != nil {
		logger.Error("Server Authentication Failure")
	}

	if resp.StatusCode != http.StatusOK {
		logger.Error("Hydrant status code not ok!")
		return errors.New("hydrant status code not ok")
	}
	return nil
}

func (c client) GetPolicies(logger hclog.Logger) ([]Policies, error) {
	// build request header
	hawkClient := GetHawkClient(c.clientConfig.ID, c.clientConfig.Key)
	header, err := hawkClient.Header("GET", DerefString(c.clientConfig.HURL)+"/policies/")
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}

	req, _ := http.NewRequest("GET", DerefString(c.clientConfig.HURL)+"/policies/", nil)
	req.Header.Set("Authorization", header)

	resp, err := c.http.Do(req)
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}
	defer resp.Body.Close()

	// authenticate server response.
	_, err = hawkClient.Authenticate(resp)
	if err != nil {
		logger.Error("Server Authentication Failure")
	}

	buff, err := ioutil.ReadAll(resp.Body)
	if err == nil {
		logger.Info("status response: " + string(buff))
		var policies []Policies
		//var policies new([]Policies)
		err = json.Unmarshal(buff, &policies)
		if err == nil {
			logger.Info("No errors unmarshalling policies!")
		} else {
			logger.Error("Errors unmarshalling policies!")
		}
		return policies, nil
	}
	return nil, err
}

func (c client) GetPolicy(logger hclog.Logger, id string) (*Policy, error) {
	// build request header
	hawkClient := GetHawkClient(c.clientConfig.ID, c.clientConfig.Key)
	header, err := hawkClient.Header("GET", DerefString(c.clientConfig.HURL)+"/policies/"+id)
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}

	req, _ := http.NewRequest("GET", DerefString(c.clientConfig.HURL)+"/policies/"+id, nil)
	req.Header.Set("Authorization", header)

	resp, err := c.http.Do(req)
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}
	defer resp.Body.Close()

	// authenticate server response.
	_, err = hawkClient.Authenticate(resp)
	if err != nil {
		logger.Error("Server Authentication Failure")
	}

	buff, err := ioutil.ReadAll(resp.Body)
	if err == nil {
		logger.Info("status response: " + string(buff))
		var policy = new(Policy)
		_ = json.Unmarshal(buff, &policy)
		return policy, nil
	}
	return nil, err
}

func (c client) RenewCert(logger hclog.Logger, id string) (*RenewResponse, error) {
	body := `{"reuseCsr": true,"csr": ""}`
	payloadBuf := new(bytes.Buffer)
	payloadBuf.WriteString(body)
	logger.Info("payloadBuf: " + body)

	// build request header
	hawkClient := GetHawkClient(c.clientConfig.ID, c.clientConfig.Key)
	header, err := hawkClient.Header("POST", DerefString(c.clientConfig.HURL)+"/certificates/"+id+"/renew/")
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}

	req, _ := http.NewRequest("POST", DerefString(c.clientConfig.HURL)+"/certificates/"+id+"/renew/", payloadBuf)
	req.Header.Set("Authorization", header)

	resp, err := c.http.Do(req)
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}
	defer resp.Body.Close()

	// authenticate server response.
	_, err = hawkClient.Authenticate(resp)
	if err != nil {
		logger.Error("Server Authentication Failure")
	}

	buff, err := ioutil.ReadAll(resp.Body)
	if err == nil {
		logger.Info("status response: " + string(buff))
		var renewResponse = new(RenewResponse)
		_ = json.Unmarshal(buff, &renewResponse)
		return renewResponse, nil
	}
	return nil, err
}
