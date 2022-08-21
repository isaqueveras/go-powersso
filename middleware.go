// Copyright (c) 2022 Isaque Veras
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package gopowersso

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

const (
	// LevelAdmin is the user level for administrators
	LevelAdmin string = "admin"
)

// Session models the session data
type Session struct {
	SessionID string `json:"session_id"`
	UserID    string `json:"user_id"`
	UserLevel string `json:"user_level"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
}

// Authorization is a middleware to check if the user is authorized to access the resource
func Authorization(secret *string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var (
			token  string
			claims jwt.MapClaims
			err    error
		)

		if token = ctx.GetHeader("Authorization"); token == "" || len(token) < 30 {
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		token = token[7:]
		if claims, err = parseJWT(token, *secret); err != nil {
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		ctx.Set("UID", claims["user_id"])
		ctx.Set("session", map[string]any{
			"user_id":    claims["user_id"],
			"user_level": claims["user_level"],
			"first_name": claims["first_name"],
			"last_name":  claims["last_name"],
			"email":      claims["email"],
		})
	}
}

// OnlyAdmin middleware to check if the user is an administrator
func OnlyAdmin() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if GetSession(ctx).UserLevel != LevelAdmin {
			ctx.AbortWithStatus(http.StatusForbidden)
			return
		}
		ctx.Next()
	}
}

// GetSession gets the session data from the context
func GetSession(ctx *gin.Context) *Session {
	value, exists := ctx.Get("session")
	if !exists {
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return nil
	}

	return value.(*Session)
}
