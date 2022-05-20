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
	"context"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	assert.Equal(&url.URL{
		Scheme:   "https",
		Host:     "issuer.example.org",
		Path:     "/authorize",
		RawQuery: "client_id=the-best-client-id&redirect_uri=&response_type=code",
	}, u)

	u = client.AuthorizeURL(TokenResponseType, &AuthorizeRequest{})
	assert.Equal(&url.URL{
		Scheme:   "https",
		Host:     "issuer.example.org",
		Path:     "/authorize",
		RawQuery: "client_id=the-best-client-id&redirect_uri=&response_type=token",
	}, u)

	request.State = "fff"
	request.RedirectURI = "http://www.example.com/callback"
	request.Scope = []string{"offline", "foo", "bar"}
	request.Extra = map[string]string{
		"foo": "bar",
		"bar": "foo foo",
	}
	u = client.AuthorizeURL(CodeResponseType, request)
	assert.Equal(&url.URL{
		Scheme:   "https",
		Host:     "issuer.example.org",
		Path:     "/authorize",
		RawQuery: "bar=foo+foo&client_id=the-best-client-id&foo=bar&redirect_uri=http%3A%2F%2Fwww.example.com%2Fcallback&response_type=code&scope=offline+foo+bar&state=fff",
	}, u)

}

func TestValidTokenRequest(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal("/custom/token", r.URL.Path)
		assert.Equal("application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

		headerAuth := r.Header.Get("Authorization")
		expectedToken :=
			base64.StdEncoding.EncodeToString([]byte(ClientId + ":" + ClientSecret))

		assert.Equal("Basic "+expectedToken, headerAuth)

		body, err := ioutil.ReadAll(r.Body)
		require.NoError(err)

		values, err := url.ParseQuery(string(body))
		require.NoError(err)

		assert.Equal("42", values.Get("code"))
		assert.Equal("https://example.com/callback", values.Get("redirect_uri"))
		assert.Equal("bar", values.Get("foo"))
		assert.Equal("qwerty", values.Get("state"))

		w.Header().Set("Content-Type", "application/json")
		payload, err := json.Marshal(map[string]interface{}{
			"access_token": "foobar",
			"token_type":   "bearer",
			"expires_in":   3600,
		})
		require.NoError(err)
		w.Write(payload)
	}))
	defer ts.Close()

	options := &Options{TokenEndpoint: "/custom/token"}
	client, err := NewClient(ts.URL, ClientId, ClientSecret, options)
	require.NoError(err)

	r, err := client.Token(context.Background(), GrantTypeAuthorizationCode, &TokenCodeRequest{
		Code:        "42",
		State:       "qwerty",
		RedirectURI: "https://example.com/callback",
		Extra: map[string]string{
			"code": "no a code",
			"foo":  "bar",
		},
	})

	assert.NoError(err)
	assert.Equal("foobar", r.AccessToken)
	assert.Equal("bearer", r.TokenType)
	assert.Equal(int64(3600), r.ExpiresIn)
}

func TestInvalidTokenRequest(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal("/custom/token", r.URL.Path)
		assert.Equal("application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

		headerAuth := r.Header.Get("Authorization")
		expectedToken :=
			base64.StdEncoding.EncodeToString([]byte(ClientId + ":" + ClientSecret))

		assert.Equal("Basic "+expectedToken, headerAuth)

		body, err := ioutil.ReadAll(r.Body)
		require.NoError(err)

		values, err := url.ParseQuery(string(body))
		require.NoError(err)

		assert.Equal("42", values.Get("code"))
		assert.Equal("https://example.com/callback", values.Get("redirect_uri"))
		assert.Equal("bar", values.Get("foo"))
		assert.Equal("qwerty", values.Get("state"))

		w.Header().Set("Content-Type", "application/json")
		payload, err := json.Marshal(map[string]interface{}{
			"error":             "invalid_request",
			"error_description": "a simple description of the error",
			"error_uri":         "http://example.com/docs/error#invalid_request",
		})
		require.NoError(err)
		w.Write(payload)
	}))
	defer ts.Close()

	options := &Options{TokenEndpoint: "/custom/token"}
	client, err := NewClient(ts.URL, ClientId, ClientSecret, options)
	require.NoError(err)

	r, err := client.Token(context.Background(), GrantTypeAuthorizationCode, &TokenCodeRequest{
		Code:        "42",
		State:       "qwerty",
		RedirectURI: "https://example.com/callback",
		Extra: map[string]string{
			"code": "no a code",
			"foo":  "bar",
		},
	})

	assert.Nil(r)
	assert.Error(err)

	oauth2Error, ok := err.(*Error)
	require.True(ok)

	assert.Equal("invalid_request", oauth2Error.Code)
	assert.Equal("a simple description of the error", oauth2Error.Description)
	assert.Equal("http://example.com/docs/error#invalid_request", oauth2Error.URI)
}
