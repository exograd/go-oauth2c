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
