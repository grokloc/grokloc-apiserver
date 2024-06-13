package client

import (
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/grokloc/grokloc-apiserver/pkg/app/jwt"
)

type Client struct {
	id, apiSecret uuid.UUID
	c             *http.Client
	u             *url.URL
	token         string
	tokenTime     time.Time
}

func New(id, apiSecret, apiUrl string, c *http.Client) (*Client, error) {
	client := Client{}

	var uuidErr error
	client.id, uuidErr = uuid.Parse(id)
	if uuidErr != nil {
		return nil, uuidErr
	}
	client.apiSecret, uuidErr = uuid.Parse(apiSecret)
	if uuidErr != nil {
		return nil, uuidErr
	}

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

func (c *Client) RefreshToken() error {
	if len(c.token) != 0 &&
		time.Since(c.tokenTime).Seconds() > float64(jwt.Expiration) {
		return nil
	}

	// tokenReqUrl
	_, tokenReqUrlErr := url.Parse(c.u.String() + "/token")
	if tokenReqUrlErr != nil {
		return tokenReqUrlErr
	}
	return nil
}
