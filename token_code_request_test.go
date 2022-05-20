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
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestTokenCodeRequestValues(t *testing.T) {
	assert := assert.New(t)

	req := &TokenCodeRequest{
		Code:        "42",
		RedirectURI: "http://example.com/callback",
		State:       "$3cr37",
		Extra: map[string]string{
			"code":         "foo",
			"redirect_uri": "foo",
			"state":        "foo",
			"foo":          "bar",
		},
	}

	values := req.Values()

	assert.Equal("42", values.Get("code"))
	assert.Equal("http://example.com/callback", values.Get("redirect_uri"))
	assert.Equal("$3cr37", values.Get("state"))
	assert.Equal("bar", values.Get("foo"))
}
