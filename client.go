// Copyright (c) 2022 Exograd SAS.
//
// Permission to use, copy, modify, and/or distribute this software for
// any purpose with or without fee is hereby granted, provided that the
// above copyright notice and this permission notice appear in all
// copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
// WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
// AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
// DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
// PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
// TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
// PERFORMANCE OF THIS SOFTWARE.

package oauth2c

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

const (
	ResponseTypeCode  = "code"
	ResponseTypeToken = "token"

	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeImplicit          = "token"
	GrantTypePasswordCreds     = "password"
	GrantTypeClientCreds       = "client_credentials"
)

var (
	defaultAuthorizeURL  = &url.URL{Path: "/authorize"}
	defaultTokenURL      = &url.URL{Path: "/token"}
	defaultIntrospectURL = &url.URL{Path: "/introspect"}
	defaultRevokeURL     = &url.URL{Path: "/revoke"}
	defaultDeviceURL     = &url.URL{Path: "/device_authorization"}
)

type Client struct {
	Issuer *url.URL

	// The client identifier.
	Id string

	// The client secret.
	Secret string

	//
	Discovery *AuthorizationServerMetadata

	// The endpoint to build the authorization request.
	AuthorizationEndpoint *url.URL

	// The endpoint used to get an access token.
	TokenEndpoint *url.URL

	// The endpoint used to introspect an access token.
	IntrospectionEndpoint *url.URL

	// The endpoint used to revoke an access token.
	RevocationEndpoint *url.URL

	// The endpoint used to create a device OAuth2 request.
	DeviceAuthorizationEndpoint *url.URL

	conn *http.Client
}

type Options struct {
	// Enable OAuth2 discovery.
	Discover bool

	// The endpoint to build the authorization request.
	AuthorizationEndpoint string

	// The endpoint used to get an access token.
	TokenEndpoint string

	// The endpoint used to introspect an access token.
	IntrospectionEndpoint string

	// The endpoint used to revoke an access token.
	RevocationEndpoint string

	// The endpoint used to create a device OAuth2 request.
	DeviceAuthorizationEndpoint string

	// The endpoint used to discover the OAuth2 server.
	DiscoveryEndpoint string

	HTTPClient *http.Client
}

func NewClient(uri, id, secret string, o *Options) (*Client, error) {
	issuer, err := url.ParseRequestURI(uri)
	if err != nil {
		return nil, fmt.Errorf("invalid issuer: %w", err)
	}

	c := Client{Issuer: issuer, Id: id, Secret: secret}

	c.conn = http.DefaultClient
	if o.HTTPClient != nil {
		c.conn = o.HTTPClient
	}

	if o.Discover {
		if err := c.discover(o.DiscoveryEndpoint); err != nil {
			return nil, fmt.Errorf("cannot discover oauth2 server: %w", err)
		}
	}

	err = c.setAuthorizationEndpoint(o.AuthorizationEndpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid authorization endpoint: %w", err)
	}

	err = c.setTokenEndpoint(o.TokenEndpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid token endpoint: %w", err)
	}

	err = c.setIntrospectionEndpoint(o.IntrospectionEndpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid introspection endpoint: %w", err)
	}

	err = c.setRevokationEndpoint(o.RevocationEndpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid revokation endpoint: %w", err)
	}

	err = c.setDeviceAuthorizationEndpoint(
		o.DeviceAuthorizationEndpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid device authorization "+
			" endpoint: %w", err)
	}

	return &c, nil
}

// AuthorizeURL returns a URL to OAuth 2.0 provider's consent page that
// asks for permissions for the required scopes explicitly.
func (c *Client) AuthorizeURL(responseType string, r *AuthorizeRequest) *url.URL {
	var u url.URL
	q := u.Query()

	q.Set("client_id", c.Id)
	q.Set("response_type", responseType)
	q.Set("redirect_uri", r.RedirectURI)

	if r.State != "" {
		q.Set("state", r.State)
	}

	if len(r.Scope) > 0 {
		q.Set("scope", strings.Join(r.Scope, " "))
	}

	for k, v := range r.Extra {
		q.Set(k, v)
	}

	u.RawQuery = q.Encode()

	return c.AuthorizationEndpoint.ResolveReference(&u)
}

func (c *Client) Token(ctx context.Context, grantType string, r TokenRequest) (*TokenResponse, error) {
	res, err := c.Token2(ctx, grantType, r)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("cannot read response body: %w", err)
	}

	// Some OAuth2 server such as GitHub return a 200 status code even though
	// the request failed. We assume that a missing or empty access token
	// means that the request failed somehow.

	var tr TokenResponse

	err = json.Unmarshal(body, &tr)

	if err != nil || tr.AccessToken == "" {
		var e Error

		if err := json.Unmarshal(body, &e); err == nil && e.Code != "" {
			e.HTTPResponse = res
			return nil, &e
		}

		return nil, fmt.Errorf("request failed with status %d: %s",
			res.StatusCode, body)
	}

	return &tr, nil
}

func (c *Client) Token2(ctx context.Context, grantType string, r TokenRequest) (*http.Response, error) {
	values := r.Values()
	values.Set("grant_type", grantType)

	reqBody := bytes.NewBufferString(values.Encode())

	req, err := http.NewRequestWithContext(ctx,
		http.MethodPost, c.TokenEndpoint.String(),
		reqBody)

	if err != nil {
		return nil, fmt.Errorf("cannot create request: %w", err)
	}

	req.Header.Add("Authorization", "Basic "+c.basicToken())
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "application/json")

	res, err := c.conn.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot send request: %w", err)
	}

	return res, nil
}

func (c *Client) Introspect(ctx context.Context, t string, r *IntrospectRequest) (*IntrospectResponse, error) {
	values := r.Values()
	values.Set("token", t)

	reqBody := bytes.NewBufferString(values.Encode())

	req, err := http.NewRequestWithContext(ctx,
		http.MethodPost, c.IntrospectionEndpoint.String(),
		reqBody)

	if err != nil {
		return nil, fmt.Errorf("cannot create request: %w", err)
	}

	req.Header.Add("Authorization", "Basic "+c.basicToken())
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "application/json")

	resp, err := c.conn.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot execute request: %w", err)
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("cannot read response body: %w",
			err)
	}

	if resp.StatusCode == http.StatusOK {
		var ir IntrospectResponse

		if err := json.Unmarshal(body, &ir); err != nil {
			return nil, fmt.Errorf("cannot unmarshal"+
				" introspect response: %w", err)
		}

		return &ir, nil
	}

	var e Error
	if err := json.Unmarshal(body, &e); err != nil {
		return nil, fmt.Errorf("cannot unmarshal error response: %w", err)
	}

	e.HTTPResponse = resp

	return nil, &e
}

func (c *Client) Revoke(ctx context.Context, t string, r *RevokeRequest) error {
	values := r.Values()
	values.Set("token", t)

	reqBody := bytes.NewBufferString(values.Encode())

	req, err := http.NewRequestWithContext(ctx,
		http.MethodPost, c.RevocationEndpoint.String(),
		reqBody)

	if err != nil {
		return fmt.Errorf("cannot create request: %w", err)
	}

	req.Header.Add("Authorization", "Basic "+c.basicToken())
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "application/json")

	resp, err := c.conn.Do(req)
	if err != nil {
		return fmt.Errorf("cannot execute request: %w", err)
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("cannot read response body: %w", err)
	}

	if resp.StatusCode == http.StatusOK {
		return nil
	}

	var e Error
	if err := json.Unmarshal(body, &e); err != nil {
		return fmt.Errorf("cannot unmarshal error response"+
			": %w", err)
	}

	e.HTTPResponse = resp

	return &e
}

func (c *Client) Device(ctx context.Context, r *DeviceRequest) (*DeviceResponse, error) {
	values := r.Values()

	reqBody := bytes.NewBufferString(values.Encode())

	req, err := http.NewRequestWithContext(ctx,
		http.MethodPost, c.DeviceAuthorizationEndpoint.String(),
		reqBody)

	if err != nil {
		return nil, fmt.Errorf("cannot create request: %w", err)
	}

	req.Header.Add("Authorization", "Basic "+c.basicToken())
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "application/json")

	resp, err := c.conn.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot execute request: %w", err)
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("cannot read response body: %w", err)
	}

	if resp.StatusCode == http.StatusOK {
		var dr DeviceResponse

		if err := json.Unmarshal(body, &dr); err != nil {
			return nil, fmt.Errorf("cannot unmarshal"+
				" introspect response: %w", err)
		}

		return &dr, nil
	}

	var e Error
	if err := json.Unmarshal(body, &e); err != nil {
		return nil, fmt.Errorf("cannot unmarshal error response"+
			": %w", err)
	}

	e.HTTPResponse = resp

	return nil, &e
}

func (c *Client) setAuthorizationEndpoint(s string) error {
	if s == "" &&
		c.Discovery != nil &&
		c.Discovery.AuthorizationEndpoint != "" {

		s = c.Discovery.AuthorizationEndpoint
	}

	if s == "" {
		u := c.Issuer.ResolveReference(defaultAuthorizeURL)
		c.AuthorizationEndpoint = u

		return nil
	}

	u, err := url.ParseRequestURI(s)
	if err != nil {
		return err
	}

	c.AuthorizationEndpoint = c.Issuer.ResolveReference(u)

	return nil
}

func (c *Client) setTokenEndpoint(s string) error {
	if s == "" &&
		c.Discovery != nil &&
		c.Discovery.TokenEndpoint != "" {

		s = c.Discovery.TokenEndpoint
	}

	if s == "" {
		u := c.Issuer.ResolveReference(defaultTokenURL)
		c.TokenEndpoint = u
		return nil
	}

	u, err := url.ParseRequestURI(s)
	if err != nil {
		return err
	}

	c.TokenEndpoint = c.Issuer.ResolveReference(u)

	return nil
}

func (c *Client) setIntrospectionEndpoint(s string) error {
	if s == "" &&
		c.Discovery != nil &&
		c.Discovery.IntrospectionEndpoint != "" {

		s = c.Discovery.IntrospectionEndpoint
	}

	if s == "" {
		u := c.Issuer.ResolveReference(defaultIntrospectURL)
		c.IntrospectionEndpoint = u
		return nil
	}

	u, err := url.ParseRequestURI(s)
	if err != nil {
		return err
	}

	c.IntrospectionEndpoint = c.Issuer.ResolveReference(u)

	return nil
}

func (c *Client) setRevokationEndpoint(s string) error {
	if s == "" &&
		c.Discovery != nil &&
		c.Discovery.RevocationEndpoint != "" {

		s = c.Discovery.RevocationEndpoint
	}

	if s == "" {
		u := c.Issuer.ResolveReference(defaultRevokeURL)
		c.RevocationEndpoint = u
		return nil
	}

	u, err := url.ParseRequestURI(s)
	if err != nil {
		return err
	}

	c.RevocationEndpoint = c.Issuer.ResolveReference(u)

	return nil
}

func (c *Client) setDeviceAuthorizationEndpoint(s string) error {
	if s == "" &&
		c.Discovery != nil &&
		c.Discovery.DeviceAuthorizationEndpoint != "" {

		s = c.Discovery.DeviceAuthorizationEndpoint
	}

	if s == "" {
		u := c.Issuer.ResolveReference(defaultDeviceURL)
		c.DeviceAuthorizationEndpoint = u
		return nil
	}

	u, err := url.ParseRequestURI(s)
	if err != nil {
		return err
	}

	c.DeviceAuthorizationEndpoint = c.Issuer.ResolveReference(u)

	return nil
}

func (c *Client) basicToken() string {
	b := []byte(c.Id + ":" + c.Secret)
	return base64.StdEncoding.EncodeToString(b)
}

func (c *Client) discover(s string) error {
	endpoint := s
	if endpoint == "" {
		u := url.URL{
			Path: "/.well-known/oauth-authorization-server",
		}

		endpoint = c.Issuer.ResolveReference(&u).String()
	}

	req, err := http.NewRequest(http.MethodGet, endpoint,
		bytes.NewReader([]byte{}))
	if err != nil {
		return fmt.Errorf("cannot create request: %w", err)
	}

	resp, err := c.conn.Do(req)
	if err != nil {
		return fmt.Errorf("cannot execute request: %w", err)
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("cannot read response body: %w", err)
	}

	if resp.StatusCode == http.StatusOK {
		var asm AuthorizationServerMetadata

		if err := json.Unmarshal(body, &asm); err != nil {
			return fmt.Errorf("cannot unmarshal discovery"+
				" response: %w", err)
		}

		c.Discovery = &asm

		return nil
	}

	var e Error
	if err := json.Unmarshal(body, &e); err != nil {
		return fmt.Errorf("cannot unmarshal error response: %w", err)
	}

	e.HTTPResponse = resp

	return &e
}
