package client

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/api/handlers/token"
	"github.com/grokloc/grokloc-apiserver/pkg/app/jwt"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/grokloc/grokloc-apiserver/pkg/safe"
)

type ResponseErr struct {
	StatusCode int
	Msg        string
}

func (r ResponseErr) Error() string {
	return fmt.Sprintf("error code: %d, msg: %v", r.StatusCode, r.Msg)
}

type Client struct {
	id        models.ID
	apiSecret safe.VarChar
	c         *http.Client
	baseUrl   *url.URL
	apiUrl    *url.URL
	token     string
	tokenTime time.Time
}

func New(idStr, apiSecretStr, apiUrl, apiVersion string, c *http.Client) (*Client, error) {
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
	client.baseUrl, uErr = url.Parse(apiUrl)
	if uErr != nil {
		return nil, uErr
	}
	client.apiUrl, uErr = url.Parse(apiUrl + app.APIPath + apiVersion)
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
	// require a thirty second buffer factor for the token expiration
	if len(client.token) != 0 &&
		time.Since(client.tokenTime).Seconds()+30.0 < float64(jwt.Expiration) {
		return nil
	}
	return client.newToken()
}

func (client *Client) newToken() error {
	tokenReqUrl, tokenReqUrlErr := url.Parse(client.baseUrl.String() + "/token")
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
		return ResponseErr{StatusCode: resp.StatusCode}
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return readErr
	}

	var tok token.JSONToken
	umErr := json.Unmarshal(body, &tok)
	if umErr != nil {
		return umErr
	}
	client.token = tok.Token
	return nil
}

func (client *Client) OK() error {
	resp, respErr := client.c.Get(client.baseUrl.String() + "/ok")
	if respErr != nil {
		return respErr
	}
	if resp.StatusCode != http.StatusOK {
		return ResponseErr{StatusCode: resp.StatusCode}
	}
	return nil
}

func (client *Client) AuthOK() error {
	okUrl, okUrlErr := url.Parse(client.apiUrl.String() + "/ok")
	if okUrlErr != nil {
		return okUrlErr
	}

	req, reqErr := http.NewRequest(http.MethodGet, okUrl.String(), nil)
	if reqErr != nil {
		return reqErr
	}

	refreshErr := client.RefreshToken()
	if refreshErr != nil {
		return refreshErr
	}

	req.Header.Add(app.IDHeader, client.id.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(client.token))
	resp, respErr := client.c.Do(req)
	if respErr != nil {
		return respErr
	}
	if resp.StatusCode != http.StatusOK {
		return ResponseErr{StatusCode: resp.StatusCode}
	}
	return nil
}
