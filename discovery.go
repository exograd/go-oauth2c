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

// AuthorizationServerMetadata describes OAuth2 provider configuration.
type AuthorizationServerMetadata struct {
	// The authorization server's issuer identifier, which is a URL
	// that uses the "https" scheme and has no query or fragment
	// components.
	Issuer string `json:"issuer"`

	// URL of the authorization server's authorization endpoint.
	AuthorizationEndpoint string `json:"authorization_endpoint"`

	// URL of the authorization server's token endpoint.
	TokenEndpoint string `json:"token_endpoint"`

	// URL of the authorization server's JWK Set document.
	JWKSURI string `json:"jwks_uri"`

	// URL of the authorization server's OAuth 2.0 Dynamic Client
	// Registration endpoint.
	RegistrationEndpoint string `json:"registration_endpoint"`

	// JSON array containing a list of the OAuth 2.0 "scope" values
	// that this authorization server supports.
	ScopesSupported []string `json:"scopes_supported"`

	// JSON array containing a list of the OAuth 2.0 "response_type"
	// values that this authorization server supports.
	ResponseTypesSupported []string `json:"response_types_supported"`

	// JSON array containing a list of the OAuth 2.0 "response_mode"
	// values that this authorization server supports, as specified
	// in "OAuth 2.0 Multiple Response Type Encoding Practices".
	ResponseModesSupported []string `json:"response_modes_supported"`

	// JSON array containing a list of the OAuth 2.0 grant type
	// values that this authorization server supports.
	GrantTypesSupported []string `json:"grant_types_supported"`

	// JSON array containing a list of client authentication methods
	// supported by this token endpoint.
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`

	// JSON array containing a list of the JWS signing algorithms
	// ("alg" values) supported by the token endpoint for the
	// signature on the JWT used to authenticate the client at the
	// token endpoint for the "private_key_jwt" and
	// "client_secret_jwt" authentication methods.
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported"`

	// URL of a page containing human-readable information that
	// developers might want or need to know when using the
	// authorization server.
	ServiceDocumentation string `json:"service_documentation"`

	// Languages and scripts supported for the user interface.
	UILocalesSupported []string `json:"ui_locales_supported"`

	// URL that the authorization server provides to the person
	// registering the client to read about the authorization
	// server's requirements on how the client can use the data
	// provided by the authorization server.
	OPPolicyURI string `json:"op_policy_uri"`

	// URL that the authorization server provides to the person
	// registering the client to read about the authorization
	// server's terms of service.
	OPTOSURI string `json:"op_tos_uri"`

	// URL of the authorization server's OAuth 2.0 revocation
	// endpoint.
	RevocationEndpoint string `json:"revocation_endpoint"`

	// JSON array containing a list of client authentication methods
	// supported by this revocation endpoint.
	RevocationEndpointAuthMethodsSupported []string `json:"revocation_endpoint_auth_methods_supported"`

	// JSON array containing a list of the JWS signing algorithms
	// ("alg" values) supported by the revocation endpoint for the
	// signature on the JWT used to authenticate the client at the
	// revocation endpoint for the "private_key_jwt" and
	// "client_secret_jwt" authentication methods.
	RevocationEndpointAuthSigningAlgValuesSupported []string `json:"revocation_endpoint_auth_signing_alg_values_supported"`

	// URL of the authorization server's OAuth 2.0 introspection
	// endpoint.
	IntrospectionEndpoint string `json:"introspection_endpoint"`

	// JSON array containing a list of client authentication methods
	// supported by this introspection endpoint.
	IntrospectionEndpointAuthMethodsSupported []string `json:"introspection_endpoint_auth_methods_supported"`

	// JSON array containing a list of the JWS signing algorithms
	// ("alg" values) supported by the introspection endpoint for
	// the signature on the JWT used to authenticate the client at
	// the introspection endpoint for the "private_key_jwt" and
	// "client_secret_jwt" authentication methods.
	IntrospectionEndpointAuthSigningAlgValuesSupported []string `json":introspection_endpoint_auth_signing_alg_values_supported"`

	// JSON array containing a list of Proof Key for Code Exchange
	// (PKCE) code challenge methods supported by this authorization
	// server.
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
}
