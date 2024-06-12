package client

import (
	"net/http"
	"net/url"

	"github.com/google/uuid"
	//"github.com/grokloc/grokloc-apiserver/pkg/app/api/handlers/token"
)

type Client struct {
	id, apiSecret uuid.UUID
	c             *http.Client
	// tok           *token.JSONToken
	u *url.URL
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
