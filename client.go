// Copyright (c) 2022 Bryan Frimin <bryan@frimin.fr>.
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
	"fmt"
	"net/url"
)

const (
	CodeResponseType  = "code"
	TokenResponseType = "token"
)

var (
	defaultAuthorizeURL  = &url.URL{Path: "/authorize"}
	defaultTokenURL      = &url.URL{Path: "/token"}
	defaultIntrospectURL = &url.URL{Path: "/introspect"}
	defaultRevokeURL     = &url.URL{Path: "/revoke"}
	defaultDeviceURL     = &url.URL{Path: "/device_authorization"}
)

type Client struct {
	Issuer                      *url.URL
	Id                          string
	Secret                      string
	Discovery                   *AuthorizationServerMetadata
	AuthorizationEndpoint       *url.URL
	TokenEndpoint               *url.URL
	IntrospectionEndpoint       *url.URL
	RevocationEndpoint          *url.URL
	DeviceAuthorizationEndpoint *url.URL
}

type Options struct {
	Discover                    bool
	AuthorizationEndpoint       string
	TokenEndpoint               string
	IntrospectionEndpoint       string
	RevocationEndpoint          string
	DeviceAuthorizationEndpoint string
}

type AuthorizeRequest struct {
	Scope       []string
	State       string
	RedirectURI string
	Extra       map[string]string
}

func NewClient(uri, id, secret string, o *Options) (*Client, error) {
	issuer, err := url.ParseRequestURI(uri)
	if err != nil {
		return nil, fmt.Errorf("invalid issuer: %w", err)
	}

	c := Client{Issuer: issuer, Id: id, Secret: secret}

	if o.Discover {
		// TODO discover
		return &c, nil
	}

	err = c.setAuthorizationEndpoint(o.AuthorizationEndpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid authorization endpoint:"+
			" %w", err)
	}

	err = c.setTokenEndpoint(o.TokenEndpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid token endpoint: %w", err)
	}

	err = c.setIntrospectionEndpoint(o.IntrospectionEndpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid introspection endpoint:"+
			" %w", err)
	}

	err = c.setRevokationEndpoint(o.RevocationEndpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid revokation endpoint:"+
			" %w", err)
	}

	err = c.setDeviceAuthorizationEndpoint(o.DeviceAuthorizationEndpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid device authorization "+
			" endpoint: %w", err)
	}

	return &c, nil
}

func (c *Client) setAuthorizationEndpoint(s string) error {
	if s == "" {
		u := c.Issuer.ResolveReference(defaultAuthorizeURL)
		c.AuthorizationEndpoint = u

		return nil
	}

	u, err := url.ParseRequestURI(s)
	if err != nil {
		return err
	}
	c.AuthorizationEndpoint = u
	return nil
}

func (c *Client) setTokenEndpoint(s string) error {
	if s == "" {
		u := c.Issuer.ResolveReference(defaultTokenURL)
		c.TokenEndpoint = u
		return nil
	}

	u, err := url.ParseRequestURI(s)
	if err != nil {
		return err
	}
	c.TokenEndpoint = u
	return nil
}

func (c *Client) setIntrospectionEndpoint(s string) error {
	if s == "" {
		u := c.Issuer.ResolveReference(defaultIntrospectURL)
		c.IntrospectionEndpoint = u
		return nil
	}

	u, err := url.ParseRequestURI(s)
	if err != nil {
		return err
	}
	c.IntrospectionEndpoint = u
	return nil
}

func (c *Client) setRevokationEndpoint(s string) error {
	if s == "" {
		u := c.Issuer.ResolveReference(defaultRevokeURL)
		c.RevocationEndpoint = u
		return nil
	}

	u, err := url.ParseRequestURI(s)
	if err != nil {
		return err
	}
	c.RevocationEndpoint = u
	return nil
}

func (c *Client) setDeviceAuthorizationEndpoint(s string) error {
	if s == "" {
		u := c.Issuer.ResolveReference(defaultDeviceURL)
		c.DeviceAuthorizationEndpoint = u
		return nil
	}

	u, err := url.ParseRequestURI(s)
	if err != nil {
		return err
	}
	c.DeviceAuthorizationEndpoint = u
	return nil
}
