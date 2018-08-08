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
	"errors"

	"github.com/dgrijalva/jwt-go"
)

// ErfClaims defines the JWT claims used in ERF.
type ErfClaims struct {
	Subject    *string `json:"sub"`
	IssuedAt   *int64  `json:"iat"`
	ExpiresAt  *int64  `json:"exp"`
	Previous   *string `json:"pre"`
	SequenceNo *int64  `json:"seq"`
}

// Valid checks all fields are non-nil
func (e *ErfClaims) Valid() error {
	// Check required fields are present
	fields := []interface{}{e.Subject, e.IssuedAt, e.ExpiresAt, e.Previous, e.SequenceNo}
	for _, f := range fields {
		if f == nil {
			return errors.New("token missing required fields")
		}
	}
	return nil
}

// ParseToken converts token bytes into an object and set of claims. It does not validate
// the token.
func ParseToken(t []byte) (*jwt.Token, *ErfClaims, error) {
	var claims ErfClaims

	token, err := jwt.ParseWithClaims(string(t), &claims, func(token *jwt.Token) (interface{}, error) {
		return jwt.UnsafeAllowNoneSignatureType, nil
	})

	return token, &claims, err
}

// Int64Ptr is a convenience method for constructing pointers from literals
func Int64Ptr(v int64) *int64 {
	return &v
}

// StringPtr is a convenience method for constructing pointers from literals
func StringPtr(v string) *string {
	return &v
}
