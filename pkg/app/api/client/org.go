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
	if resp.StatusCode != http.StatusCreated {
		return nil, ResponseErr{StatusCode: resp.StatusCode}
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

func (client *Client) ReadOrg(id models.ID) (*org.Org, error) {
	readOrgUrl, readOrgUrlErr := url.Parse(client.apiUrl.String() + "/org/" + id.String())
	if readOrgUrlErr != nil {
		return nil, readOrgUrlErr
	}

	req, reqErr := http.NewRequest(http.MethodGet, readOrgUrl.String(), nil)
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
	if resp.StatusCode != http.StatusOK {
		return nil, ResponseErr{StatusCode: resp.StatusCode}
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

func (client *Client) ReadOrgUsers(id models.ID) ([]models.ID, error) {
	readOrgUrl, readOrgUrlErr := url.Parse(client.apiUrl.String() + "/org/" + id.String() + "/users")
	if readOrgUrlErr != nil {
		return nil, readOrgUrlErr
	}

	req, reqErr := http.NewRequest(http.MethodGet, readOrgUrl.String(), nil)
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
	if resp.StatusCode != http.StatusOK {
		return nil, ResponseErr{StatusCode: resp.StatusCode}
	}

	defer resp.Body.Close()
	dec := json.NewDecoder(resp.Body)
	var userIDs []models.ID
	decErr := dec.Decode(&userIDs)
	if decErr != nil {
		return nil, decErr
	}

	return userIDs, nil
}

func (client *Client) UpdateOrgOwner(id models.ID, owner models.ID) (*org.Org, error) {
	updateOrgUrl, updateOrgUrlErr := url.Parse(client.apiUrl.String() + "/org/" + id.String())
	if updateOrgUrlErr != nil {
		return nil, updateOrgUrlErr
	}

	bs, bsErr := json.Marshal(org.UpdateOwnerEvent{Owner: owner})
	if bsErr != nil {
		return nil, bsErr
	}

	req, reqErr := http.NewRequest(http.MethodPut, updateOrgUrl.String(), bytes.NewReader(bs))
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
	if resp.StatusCode != http.StatusOK {
		return nil, ResponseErr{StatusCode: resp.StatusCode}
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

func (client *Client) UpdateOrgStatus(id models.ID, status models.Status) (*org.Org, error) {
	updateOrgUrl, updateOrgUrlErr := url.Parse(client.apiUrl.String() + "/org/" + id.String())
	if updateOrgUrlErr != nil {
		return nil, updateOrgUrlErr
	}

	bs, bsErr := json.Marshal(org.UpdateStatusEvent{Status: status})
	if bsErr != nil {
		return nil, bsErr
	}

	req, reqErr := http.NewRequest(http.MethodPut, updateOrgUrl.String(), bytes.NewReader(bs))
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
	if resp.StatusCode != http.StatusOK {
		return nil, ResponseErr{StatusCode: resp.StatusCode}
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

func (client *Client) DeleteOrg(id models.ID) error {
	deleteOrgUrl, deleteOrgUrlErr := url.Parse(client.apiUrl.String() + "/org/" + id.String())
	if deleteOrgUrlErr != nil {
		return deleteOrgUrlErr
	}

	req, reqErr := http.NewRequest(http.MethodDelete, deleteOrgUrl.String(), nil)
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
	if resp.StatusCode != http.StatusNoContent {
		return ResponseErr{StatusCode: resp.StatusCode}
	}

	return nil
}
