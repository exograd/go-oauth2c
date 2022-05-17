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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

var (
	Issuer       = "https://issuer.example.org"
	ClientId     = "the-best-client-id"
	ClientSecret = "this-is-a-strong-client-secret"
)

func TestNewClient(t *testing.T) {
	assert := assert.New(t)

	options := &Options{}

	client, err := NewClient("++", ClientId, ClientSecret, options)
	assert.Error(err)
	assert.Nil(client)

	client, err = NewClient(Issuer, ClientId, ClientSecret, options)
	assert.NoError(err)
	assert.Equal(ClientId, client.Id)
	assert.Equal(ClientSecret, client.Secret)
	assert.Equal("/authorize", client.AuthorizationEndpoint.Path)
	assert.Equal("/token", client.TokenEndpoint.Path)
	assert.Equal("/introspect", client.IntrospectionEndpoint.Path)
	assert.Equal("/revoke", client.RevocationEndpoint.Path)
	assert.Equal("/device_authorization", client.DeviceAuthorizationEndpoint.Path)

	options.AuthorizationEndpoint = "/new_authorize"
	options.TokenEndpoint = "/new_token"
	options.IntrospectionEndpoint = "/new_introspect"
	options.RevocationEndpoint = "/new_revoke"
	options.DeviceAuthorizationEndpoint = "/new_device"
	client, err = NewClient(Issuer, ClientId, ClientSecret, options)
	assert.NoError(err)
	assert.Equal(ClientId, client.Id)
	assert.Equal(ClientSecret, client.Secret)
	assert.Equal("/new_authorize", client.AuthorizationEndpoint.Path)
	assert.Equal("/new_token", client.TokenEndpoint.Path)
	assert.Equal("/new_introspect", client.IntrospectionEndpoint.Path)
	assert.Equal("/new_revoke", client.RevocationEndpoint.Path)
	assert.Equal("/new_device", client.DeviceAuthorizationEndpoint.Path)

	options.AuthorizationEndpoint = "++"
	client, err = NewClient(Issuer, ClientId, ClientSecret, options)
	assert.Error(err)
	assert.Nil(client)
	options.AuthorizationEndpoint = "/token"

	options.TokenEndpoint = "++"
	client, err = NewClient(Issuer, ClientId, ClientSecret, options)
	assert.Error(err)
	assert.Nil(client)
	options.TokenEndpoint = "/token"

	options.IntrospectionEndpoint = "++"
	client, err = NewClient(Issuer, ClientId, ClientSecret, options)
	assert.Error(err)
	assert.Nil(client)
	options.IntrospectionEndpoint = "/introspect"

	options.RevocationEndpoint = "++"
	client, err = NewClient(Issuer, ClientId, ClientSecret, options)
	assert.Error(err)
	assert.Nil(client)
	options.RevocationEndpoint = "/revoke"

	options.DeviceAuthorizationEndpoint = "++"
	client, err = NewClient(Issuer, ClientId, ClientSecret, options)
	assert.Error(err)
	assert.Nil(client)
	options.RevocationEndpoint = "/device"
}

func TestAuthorizaURL(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	client, err := NewClient(Issuer, ClientId, ClientSecret, &Options{})
	require.NoError(err)

	request := &AuthorizeRequest{}

	u := client.AuthorizeURL(CodeResponseType, request)
	assert.Equal("https://issuer.example.org/authorize?client_id=the-best-client-id&redirect_uri=&response_type=code", u)

	u = client.AuthorizeURL(TokenResponseType, &AuthorizeRequest{})
	assert.Equal("https://issuer.example.org/authorize?client_id=the-best-client-id&redirect_uri=&response_type=token", u)

	request.State = "fff"
	request.RedirectURI = "http://www.example.com/callback"
	request.Scope = []string{"offline", "foo", "bar"}
	request.Extra = map[string]string{
		"foo": "bar",
		"bar": "foo foo",
	}
	u = client.AuthorizeURL(CodeResponseType, request)
	assert.Equal("https://issuer.example.org/authorize?bar=foo+foo&client_id=the-best-client-id&foo=bar&redirect_uri=http%3A%2F%2Fwww.example.com%2Fcallback&response_type=code&scope=offline+foo+bar&state=fff", u)

}
