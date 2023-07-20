package azure

import (
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

// https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service?tabs=linux#sample-1-validate-that-the-vm-is-running-in-azure

//go:embed certs/*.pem
var f embed.FS

type MetadataResponse struct {
	Signature string `json:"signature"`
}

type AzureVerifier struct {
	IntermediateCertificateURLs map[string]string
	CAFile                      string
}

func NewAzureVerifier() *AzureVerifier {
	return &AzureVerifier{
		// https://www.microsoft.com/pkiops/docs/repository.htm
		IntermediateCertificateURLs: map[string]string{
			"Microsoft Azure TLS Issuing CA 01": "https://www.microsoft.com/pki/certs/Microsoft%20Azure%20TLS%20Issuing%20CA%2001.cer",
			"Microsoft Azure TLS Issuing CA 02": "https://www.microsoft.com/pki/certs/Microsoft%20Azure%20TLS%20Issuing%20CA%2002.cer",
			"Microsoft Azure TLS Issuing CA 03": "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20TLS%20Issuing%20CA%2005.cer",
			"Microsoft Azure TLS Issuing CA 04": "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20TLS%20Issuing%20CA%2006.cer",
			"Microsoft Azure TLS Issuing CA 05": "http://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20TLS%20Issuing%20CA%2005.cer",
			"Microsoft Azure TLS Issuing CA 06": "http://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20TLS%20Issuing%20CA%2006.cer",
		},
		CAFile: "DigiCert_Global_Root_CA.pem",
	}
}

func (av *AzureVerifier) Verify() bool {
	dir, err := os.MkdirTemp(os.TempDir(), "cloud-verify-*")
	if err != nil {
		return false
	}
	defer func() { _ = os.RemoveAll(dir) }()

	signature := av.fetchSignature()

	if signature == nil {
		return false
	}

	if err := os.WriteFile(filepath.Join(dir, "decodedsignature"), signature, 0700); err != nil {
		return false
	}

	if err := av.convertSignatureToPKCS7(filepath.Join(dir, "decodedsignature"), filepath.Join(dir, "sign.pk7")); err != nil {
		return false
	}

	if err := av.getPublickKeyFromPKCS7(filepath.Join(dir, "decodedsignature"), filepath.Join(dir, "signer.pem")); err != nil {
		return false
	}

	if err := av.verifyContents(filepath.Join(dir, "sign.pk7")); err != nil {
		return false
	}

	if err := av.downloadIntermediateCertificates(dir); err != nil {
		return false
	}

	for k := range av.IntermediateCertificateURLs {
		if err := av.convertDERToPEM(filepath.Join(dir, fmt.Sprintf("%s.cer", k)), filepath.Join(dir, fmt.Sprintf("%s.pem", k))); err != nil {
			return false
		}
	}

	if err := av.getCAFile(filepath.Join(dir, "ca.pem")); err != nil {
		return false
	}

	valid := false
	for k := range av.IntermediateCertificateURLs {
		if err := av.verifyChain(filepath.Join(dir, "ca.pem"), filepath.Join(dir, fmt.Sprintf("%s.pem", k)), filepath.Join(dir, "signer.pem")); err == nil {
			valid = true
			break
		}
	}

	return valid
}

func (av *AzureVerifier) downloadIntermediateCertificates(path string) error {
	for k := range av.IntermediateCertificateURLs {
		ic := av.IntermediateCertificateURLs[k]
		file, err := os.Create(filepath.Join(path, fmt.Sprintf("%s.cer", k)))
		if err != nil {
			return err
		}
		defer file.Close()

		response, err := http.Get(ic)
		if err != nil {
			return err
		}
		defer response.Body.Close()

		_, err = io.Copy(file, response.Body)
		if err != nil {
			return err
		}
	}

	return nil
}

func (av *AzureVerifier) verifyContents(path string) error {
	cmd := exec.Command("openssl", "smime", "-verify", "-in", path, "-inform", "pem", "-noverify")

	return cmd.Run()
}

func (av *AzureVerifier) getCAFile(path string) error {
	caf, err := f.ReadFile(filepath.Join("certs", av.CAFile))
	if err != nil {
		return err
	}

	return os.WriteFile(path, caf, 0700)
}

func (av *AzureVerifier) verifyChain(ca string, intermediate string, signer string) error {

	cmd := exec.Command("openssl", "verify", "-verbose", "-CAfile", ca, "-untrusted", intermediate, signer)

	return cmd.Run()
}

func (av *AzureVerifier) getPublickKeyFromPKCS7(path string, npath string) error {
	cmd := exec.Command("openssl", "pkcs7", "-in", path, "-inform", "DER", "-print_certs", "-out", npath)

	return cmd.Run()
}

func (av *AzureVerifier) convertDERToPEM(path string, npath string) error {
	cmd := exec.Command("openssl", "x509", "-inform", "der", "-in", path, "-out", npath)

	return cmd.Run()
}

func (av *AzureVerifier) convertSignatureToPKCS7(path string, npath string) error {
	cmd := exec.Command("openssl", "pkcs7", "-in", path, "-inform", "DER", "-out", npath)

	return cmd.Run()
}

func (av *AzureVerifier) fetchSignature() []byte {
	client := &http.Client{}
	req, err := http.NewRequest("GET", "http://169.254.169.254/metadata/attested/document?api-version=2020-09-01", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Metadata", "True")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	var metadata MetadataResponse
	if err := json.Unmarshal(body, &metadata); err != nil {
		return nil
	}

	decodedSignature, err := base64.StdEncoding.DecodeString(metadata.Signature)
	if err != nil {
		return nil
	}

	return decodedSignature
}
