// Copyright 2018 Thales UK Limited
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
// Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
// WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
package erfcommon

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseToken(t *testing.T) {
	// was produced by jwt.io
	const jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJkZDI4ODJkZS00NWRjLTRkMmEtYTY1OC03YWZjOTQxYzk5YzciLCJpYXQiOjE1MTk2NDU5NTcsImV4cCI6MTUxOTY0Njk1NywicHJlIjoiMjdiYjllYTAtMzk2My00NDViLWI0MzUtMzQ2MWU2NjBkMTgwIiwic2VxIjoxfQ."

	expectedClaims := &ErfClaims{
		Subject:    StringPtr("dd2882de-45dc-4d2a-a658-7afc941c99c7"),
		IssuedAt:   Int64Ptr(1519645957),
		ExpiresAt:  Int64Ptr(1519646957),
		Previous:   StringPtr("27bb9ea0-3963-445b-b435-3461e660d180"),
		SequenceNo: Int64Ptr(1),
	}

	_, claims, err := ParseToken([]byte(jwt))
	if assert.NoError(t, err) {
		assert.Equal(t, expectedClaims, claims)
	}
}
