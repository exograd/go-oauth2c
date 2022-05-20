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

type TokenResponse struct {
	// AccessToken is the token that authorizes and authenticates the
	// requests.
	AccessToken string `json:"access_token"`

	// TokenType is the type of token (e.g. Bearer).
	TokenType string `json:"token_type"`

	// Expiry is the optional expiration time of the access token.
	ExpiresIn int64 `json:"expires_in"`

	// RefreshToken is a token that's used by the application (as
	// opposed to the user) to refresh the access token if it
	// expires.
	RefreshToken string `json:"refresh_token"`

	// Scope associated with the access token.
	Scope string `json:"scope"`
}
