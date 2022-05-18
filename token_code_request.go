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

type TokenCodeRequest struct {
	Code        string
	RedirectURI string
	State       string
	Extra       map[string]string
}

func (t *TokenCodeRequest) Values() url.Values {
	q := url.Values{}

	for k, v := range t.Extra {
		q.Set(k, v)
	}

	q.Set("code", t.Code)

	if t.RedirectURI != "" {
		q.Set("redirect_uri", t.RedirectURI)
	}

	if t.State != "" {
		q.Set("state", t.State)
	}

	return q
}
