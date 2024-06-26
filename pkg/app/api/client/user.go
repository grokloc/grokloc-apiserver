package client

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/user"
	"github.com/grokloc/grokloc-apiserver/pkg/app/jwt"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/grokloc/grokloc-apiserver/pkg/safe"
)

func (client *Client) CreateUser(
	displayName safe.VarChar,
	email safe.VarChar,
	org models.ID,
	password safe.Password,
) (*user.User, error) {
	createUserUrl, createUserUrlErr := url.Parse(client.apiUrl.String() + "/user")
	if createUserUrlErr != nil {
		return nil, createUserUrlErr
	}

	bs, bsErr := json.Marshal(user.CreateEvent{
		DisplayName: displayName,
		Email:       email,
		Org:         org,
		Password:    password,
	})
	if bsErr != nil {
		return nil, bsErr
	}

	req, reqErr := http.NewRequest(http.MethodPost, createUserUrl.String(), bytes.NewReader(bs))
	if reqErr != nil {
		return nil, reqErr
	}

	refreshErr := client.RefreshToken()
	if refreshErr != nil {
		return nil, refreshErr
	}

	req.Header.Add(app.IDHeader, client.id.String())
	req.Header.Add(app.AuthorizationHeader, jwt.SignedStringToHeaderValue(client.token))
	resp, respErr := client.c.Do(req)
	if respErr != nil {
		return nil, respErr
	}
	if resp.StatusCode != http.StatusCreated {
		return nil, ResponseErr{StatusCode: resp.StatusCode}
	}

	defer resp.Body.Close()
	dec := json.NewDecoder(resp.Body)
	var u user.User
	decErr := dec.Decode(&u)
	if decErr != nil {
		return nil, decErr
	}

	return &u, nil
}
