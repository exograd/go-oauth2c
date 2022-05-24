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
	"net/http"
)

type Error struct {
	// A single ASCII error code.
	Code string `json:"error"`

	// Human-readable ASCII text providing additional information,
	// used to assist the client developer in understanding the
	// error that occurred.
	Description string `json:"error_description"`

	// A URI identifying a human-readable web page with information
	// about the error, used to provide the client developer with
	// additional information about the error
	URI string `json:"error_uri"`

	HttpResponse *http.Response
}

func (e *Error) Error() string {
	return e.Code
}

func GetRequestError(r *http.Request) error {
	q := r.URL.Query()

	if q.Get("error") == "" {
		return nil
	}

	return &Error{
		Code:        q.Get("error"),
		Description: q.Get("error_description"),
		URI:         q.Get("error_uri"),
	}
}
