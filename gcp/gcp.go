package gcp

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/google/uuid"
	"google.golang.org/api/idtoken"
)

// https://cloud.google.com/compute/docs/instances/verifying-instance-identity

type GCPVerifier struct {
	Audience string
}

func NewGCPVerifier() *GCPVerifier {
	return &GCPVerifier{
		Audience: fmt.Sprintf("https://cloud.verify/%s", uuid.NewString()),
	}
}

func (v *GCPVerifier) Verify() bool {
	token, err := v.getInstanceIdentityToken(v.Audience)
	if err != nil {
		return false
	}

	return v.verifyToken(token) == nil
}

func (v *GCPVerifier) verifyToken(token string) error {
	ctx := context.Background()

	// Validate the ID token with the provided audience
	_, err := idtoken.Validate(ctx, token, v.Audience)

	return err
}

func (v *GCPVerifier) getInstanceIdentityToken(audience string) (string, error) {
	u, err := url.Parse("http://metadata/computeMetadata/v1/instance/service-accounts/default/identity")
	if err != nil {
		return "", err
	}

	query := u.Query()
	query.Add("audience", audience)

	u.RawQuery = query.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return "", err
	}

	req.Header.Add("Metadata-Flavor", "Google")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(res.Body, 1024*100))

	return string(body), nil
}
