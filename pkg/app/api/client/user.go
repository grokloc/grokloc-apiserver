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

func (client *Client) ReadUser(id models.ID) (*user.User, error) {
	readUserUrl, readUserUrlErr := url.Parse(client.apiUrl.String() + "/user/" + id.String())
	if readUserUrlErr != nil {
		return nil, readUserUrlErr
	}

	req, reqErr := http.NewRequest(http.MethodGet, readUserUrl.String(), nil)
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
	var u user.User
	decErr := dec.Decode(&u)
	if decErr != nil {
		return nil, decErr
	}

	return &u, nil
}

func (client *Client) UpdateUserAPISecret(id models.ID) (*user.User, error) {
	updateUserUrl, updateUserUrlErr := url.Parse(client.apiUrl.String() + "/user/" + id.String())
	if updateUserUrlErr != nil {
		return nil, updateUserUrlErr
	}

	bs, bsErr := json.Marshal(user.UpdateAPISecretEvent{GenerateAPISecret: true})
	if bsErr != nil {
		return nil, bsErr
	}

	req, reqErr := http.NewRequest(http.MethodPut, updateUserUrl.String(), bytes.NewReader(bs))
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
	var u user.User
	decErr := dec.Decode(&u)
	if decErr != nil {
		return nil, decErr
	}

	// token must be hard-refreshed as API secret has changed
	// but only if the client is the same as the target id
	// (i.e. client's own API secret has changed)
	if client.id == id {
		client.apiSecret = u.APISecret
		tokenErr := client.newToken()
		if tokenErr != nil {
			return nil, tokenErr
		}
	}

	return &u, nil
}

func (client *Client) UpdateUserDisplayName(id models.ID, displayName safe.VarChar) (*user.User, error) {
	updateUserUrl, updateUserUrlErr := url.Parse(client.apiUrl.String() + "/user/" + id.String())
	if updateUserUrlErr != nil {
		return nil, updateUserUrlErr
	}

	bs, bsErr := json.Marshal(user.UpdateDisplayNameEvent{DisplayName: displayName})
	if bsErr != nil {
		return nil, bsErr
	}

	req, reqErr := http.NewRequest(http.MethodPut, updateUserUrl.String(), bytes.NewReader(bs))
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
	var u user.User
	decErr := dec.Decode(&u)
	if decErr != nil {
		return nil, decErr
	}

	return &u, nil
}

func (client *Client) UpdateUserPassword(id models.ID, password safe.Password) (*user.User, error) {
	updateUserUrl, updateUserUrlErr := url.Parse(client.apiUrl.String() + "/user/" + id.String())
	if updateUserUrlErr != nil {
		return nil, updateUserUrlErr
	}

	bs, bsErr := json.Marshal(user.UpdatePasswordEvent{Password: password})
	if bsErr != nil {
		return nil, bsErr
	}

	req, reqErr := http.NewRequest(http.MethodPut, updateUserUrl.String(), bytes.NewReader(bs))
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
	var u user.User
	decErr := dec.Decode(&u)
	if decErr != nil {
		return nil, decErr
	}

	return &u, nil
}

func (client *Client) UpdateUserStatus(id models.ID, status models.Status) (*user.User, error) {
	updateUserUrl, updateUserUrlErr := url.Parse(client.apiUrl.String() + "/user/" + id.String())
	if updateUserUrlErr != nil {
		return nil, updateUserUrlErr
	}

	bs, bsErr := json.Marshal(user.UpdateStatusEvent{Status: status})
	if bsErr != nil {
		return nil, bsErr
	}

	req, reqErr := http.NewRequest(http.MethodPut, updateUserUrl.String(), bytes.NewReader(bs))
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
	var u user.User
	decErr := dec.Decode(&u)
	if decErr != nil {
		return nil, decErr
	}

	return &u, nil
}
