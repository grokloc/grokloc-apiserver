package client

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/grokloc/grokloc-apiserver/pkg/app"
	"github.com/grokloc/grokloc-apiserver/pkg/app/admin/org"
	"github.com/grokloc/grokloc-apiserver/pkg/app/jwt"
	"github.com/grokloc/grokloc-apiserver/pkg/app/models"
	"github.com/grokloc/grokloc-apiserver/pkg/safe"
)

func (client *Client) CreateOrg(
	name, ownerDisplayName, ownerEmail safe.VarChar,
	ownerPassword safe.Password,
	role models.Role,
) (*org.Org, error) {
	createOrgUrl, createOrgUrlErr := url.Parse(client.apiUrl.String() + "/org")
	if createOrgUrlErr != nil {
		return nil, createOrgUrlErr
	}

	bs, bsErr := json.Marshal(org.CreateEvent{
		Name:             name,
		OwnerDisplayName: ownerDisplayName,
		OwnerEmail:       ownerEmail,
		OwnerPassword:    ownerPassword,
		Role:             role,
	})
	if bsErr != nil {
		return nil, bsErr
	}

	req, reqErr := http.NewRequest(http.MethodPost, createOrgUrl.String(), bytes.NewReader(bs))
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

	defer resp.Body.Close()
	dec := json.NewDecoder(resp.Body)
	var o org.Org
	decErr := dec.Decode(&o)
	if decErr != nil {
		return nil, decErr
	}

	return &o, nil
}
