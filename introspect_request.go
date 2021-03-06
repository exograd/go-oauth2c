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
	"net/url"
)

type IntrospectRequest struct {
	// A hint about the type of the token submitted for
	// introspection.
	TokenTypeHint string

	// Custom parameters which is not part of the OAuth2
	// specification.
	Extra map[string]string
}

func (i *IntrospectRequest) Values() url.Values {
	q := url.Values{}

	for k, v := range i.Extra {
		q.Set(k, v)
	}

	if i.TokenTypeHint != "" {
		q.Set("token_type_hint", i.TokenTypeHint)
	}

	return q
}
