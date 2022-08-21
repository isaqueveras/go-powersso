// Copyright (c) 2022 Isaque Veras
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package gopowersso

import (
	"errors"

	"github.com/golang-jwt/jwt/v4"
)

// parseJWT verifies and parses JWT token and returns its claims.
func parseJWT(token, verificationKey string) (jwt.MapClaims, error) {
	var (
		parser      = jwt.NewParser(jwt.WithValidMethods([]string{"HS256"}))
		parsedToken *jwt.Token
		err         error
	)

	if parsedToken, err = parser.Parse(token, func(t *jwt.Token) (interface{}, error) {
		return []byte(verificationKey), nil
	}); err != nil {
		return nil, err
	}

	if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok && parsedToken.Valid {
		return claims, nil
	}

	return nil, errors.New("unable to parse token")
}
