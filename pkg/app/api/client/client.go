package client

import (
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/jwt"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/grokloc/grokloc-apiserver/pkg/safe"
)

type Client struct {
	id        models.ID
	apiSecret safe.VarChar
	c         *http.Client
	u         *url.URL
	token     string
	tokenTime time.Time
}

func New(idStr, apiSecretStr, apiUrl string, c *http.Client) (*Client, error) {
	client := Client{}

	id := new(models.ID)
	idErr := id.Scan(idStr)
	if idErr != nil {
		return nil, idErr
	}
	client.id = *id

	apiSecret, apiSecretErr := safe.NewVarChar(apiSecretStr)
	if apiSecretErr != nil {
		return nil, apiSecretErr
	}
	client.apiSecret = *apiSecret

	var uErr error
	client.u, uErr = url.Parse(apiUrl)
	if uErr != nil {
		return nil, uErr
	}

	if c != nil {
		client.c = c
	} else {
		client.c = &http.Client{}
	}
	return &client, nil
}

func (client *Client) RefreshToken() error {
	if len(client.token) != 0 &&
		time.Since(client.tokenTime).Seconds() > float64(jwt.Expiration) {
		return nil
	}

	tokenReqUrl, tokenReqUrlErr := url.Parse(client.u.String() + "/token")
	if tokenReqUrlErr != nil {
		return tokenReqUrlErr
	}

	tokenReqStr := jwt.EncodeTokenRequest(client.id, client.apiSecret.String())
	req := http.Request{
		URL:    tokenReqUrl,
		Method: http.MethodPost,
		Header: map[string][]string{
			app.IDHeader:           {client.id.String()},
			app.TokenRequestHeader: {tokenReqStr},
		},
	}

	resp, postErr := client.c.Do(&req)
	if postErr != nil {
		return postErr
	}
	if resp.StatusCode != http.StatusOK {
		return errors.New("token request failed")
	}
	return nil
}
