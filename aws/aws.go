package aws

import (
	"embed"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"time"
)

// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/verify-pkcs7.html
//
// Instance metadata needs to be enabled

//go:embed certs/*.pem
var f embed.FS

type AWSVerifier struct{}

func NewAWSVerifier() *AWSVerifier {
	return &AWSVerifier{}
}

func (v *AWSVerifier) Verify() bool {
	err := v.validateMetadataServer()

	return err == nil
}

func (v *AWSVerifier) awsMetadataRequest(method string, rpath string, headers map[string]string) ([]byte, map[string]string, error) {
	u, err := url.Parse("http://169.254.169.254")
	if err != nil {
		return nil, nil, err
	}

	u.Path = path.Join(u.Path, rpath)

	req, err := http.NewRequest(method, u.String(), nil)
	for k := range headers {
		req.Header.Add(k, headers[k])
	}

	if err != nil {
		return nil, nil, err
	}

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*100))
	if err != nil {
		return nil, nil, err
	}

	var respHeaders = make(map[string]string)

	for k := range resp.Header {
		respHeaders[k] = resp.Header.Get(k)
	}

	return body, headers, nil
}

func (v *AWSVerifier) validateMetadataServer() error {
	var smimeData string
	var err error

	smimeData, err = v.getInstanceIdentityPKCS7IMDSv2()
	if err != nil {
		smimeData, err = v.getInstanceIdentityPKCS7IMDSv1()
		if err != nil {
			return err
		}
	}

	dir, err := os.MkdirTemp(os.TempDir(), "cloud-verify-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()

	if err := os.WriteFile(filepath.Join(dir, "pkcs7"), []byte(smimeData), 0700); err != nil {
		return err
	}

	regionCert, err := v.getRegionCertificate()
	if err != nil {
		return err
	}

	if err := os.WriteFile(filepath.Join(dir, "certificate"), []byte(regionCert), 0700); err != nil {
		return err
	}

	cmd := exec.Command("openssl", "smime", "-verify", "-in", filepath.Join(dir, "pkcs7"), "-inform", "PEM", "-certfile", filepath.Join(dir, "certificate"), "-noverify")

	return cmd.Run()
}

func (v *AWSVerifier) getRegionCertificate() (string, error) {
	crt, err := f.ReadFile(filepath.Join("certs", fmt.Sprintf("%s.pem", v.getRegion())))

	return string(crt), err
}

func (v *AWSVerifier) getRegion() string {
	region, _, _ := v.awsMetadataRequest("GET", "/latest/meta-data/placement/region", map[string]string{"X-aws-ec2-metadata-token-ttl-seconds": "60"})

	return string(region)
}

func (v *AWSVerifier) wrapPKCS7(rsa []byte, _ map[string]string, err error) (string, error) {
	return fmt.Sprintf("-----BEGIN PKCS7-----\n%s\n-----END PKCS7-----", string(rsa)), err
}

func (v *AWSVerifier) getInstanceIdentityPKCS7IMDSv1() (string, error) {
	return v.wrapPKCS7(v.awsMetadataRequest("GET", "/latest/dynamic/instance-identity/pkcs7", nil))
}

func (v *AWSVerifier) getInstanceIdentityPKCS7IMDSv2() (string, error) {
	token, err := v.getIMDSv2Token()
	if err != nil {
		return "", nil
	}

	return v.wrapPKCS7(v.awsMetadataRequest("GET", "/latest/dynamic/instance-identity/pkcs7", map[string]string{"X-aws-ec2-metadata-token": token}))
}

func (v *AWSVerifier) getIMDSv2Token() (string, error) {
	token, _, err := v.awsMetadataRequest("PUT", "/latest/api/token", map[string]string{"X-aws-ec2-metadata-token-ttl-seconds": "60"})

	return string(token), err
}
