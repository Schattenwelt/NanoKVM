package middleware

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	log "github.com/sirupsen/logrus"

	"NanoKVM-Server/config"
)

// Role constants mirrored here to avoid circular imports.
const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleViewer   = "viewer"
)

type Token struct {
	Username     string `json:"username"`
	Role         string `json:"role"`
	TokenVersion int    `json:"tokenVersion"`
	jwt.RegisteredClaims
}

// AccountResolver is registered by the auth service at startup. It lets the JWT
// middleware validate a token against live account state (role, token version,
// enabled flag) without importing the auth package, which would create an
// import cycle (auth already imports this package for GenerateJWT).
var AccountResolver func(username string) (role string, tokenVersion int, enabled bool, err error)

// CheckToken allows any authenticated user whose account is still valid.
func CheckToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, ok := parseTokenFromContext(c)
		if !ok {
			abortUnauthorized(c)
			return
		}
		if !applyLiveAccount(c, token) {
			return
		}
		c.Next()
	}
}

// applyLiveAccount validates a parsed token against current account state and
// stores the live username and role in the context. It aborts with 401 if the
// account was deleted, disabled, or the token was revoked (token version no
// longer matches). The role is taken from the store, never from the JWT, so a
// demoted user loses access immediately instead of at token expiry. When
// authentication is disabled the synthetic admin passes through unchecked.
func applyLiveAccount(c *gin.Context, token *Token) bool {
	if config.GetInstance().Authentication == "disable" {
		c.Set("username", token.Username)
		c.Set("role", token.Role)
		return true
	}
	if AccountResolver == nil {
		// Fail closed: without a resolver we cannot verify revocation.
		abortUnauthorized(c)
		return false
	}
	role, version, enabled, err := AccountResolver(token.Username)
	if err != nil || !enabled || version != token.TokenVersion {
		abortUnauthorized(c)
		return false
	}
	c.Set("username", token.Username)
	c.Set("role", role)
	return true
}

// RequireRole returns a middleware that only allows users with one of the given roles.
func RequireRole(roles ...string) gin.HandlerFunc {
	allowed := make(map[string]bool, len(roles))
	for _, r := range roles {
		allowed[r] = true
	}
	return func(c *gin.Context) {
		role, exists := c.Get("role")
		if !exists {
			abortForbidden(c)
			return
		}
		if !allowed[role.(string)] {
			abortForbidden(c)
			return
		}
		c.Next()
	}
}

func CheckLoopbackInternalToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		if allowByLoopbackInternalToken(c.Request) {
			c.Next()
			return
		}
		abortUnauthorized(c)
	}
}

func CheckTokenOrLoopbackInternalToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		if token, ok := parseTokenFromContext(c); ok {
			if applyLiveAccount(c, token) {
				c.Next()
			}
			return
		}
		if allowByLoopbackInternalToken(c.Request) {
			c.Next()
			return
		}
		abortUnauthorized(c)
	}
}

func parseTokenFromContext(c *gin.Context) (*Token, bool) {
	conf := config.GetInstance()
	if conf.Authentication == "disable" {
		c.Set("username", "admin")
		c.Set("role", RoleAdmin)
		return &Token{Username: "admin", Role: RoleAdmin}, true
	}
	cookie, err := c.Cookie("nano-kvm-token")
	if err != nil {
		return nil, false
	}
	token, err := ParseJWT(cookie)
	if err != nil {
		return nil, false
	}
	return token, true
}

func abortUnauthorized(c *gin.Context) {
	c.JSON(http.StatusUnauthorized, "unauthorized")
	c.Abort()
}

func abortForbidden(c *gin.Context) {
	c.JSON(http.StatusForbidden, "forbidden: insufficient permissions")
	c.Abort()
}

func GenerateJWT(username, role string, tokenVersion int) (string, error) {
	conf := config.GetInstance()
	expireDuration := time.Duration(conf.JWT.RefreshTokenDuration) * time.Second
	now := time.Now()
	claims := Token{
		Username:     username,
		Role:         role,
		TokenVersion: tokenVersion,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   username,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(expireDuration)),
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString([]byte(conf.JWT.SecretKey))
}

func ParseJWT(jwtToken string) (*Token, error) {
	conf := config.GetInstance()
	t, err := jwt.ParseWithClaims(jwtToken, &Token{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(conf.JWT.SecretKey), nil
	},
		jwt.WithValidMethods([]string{"HS256"}), // reject alg confusion / alg=none
		jwt.WithExpirationRequired(),            // tokens must carry an expiry
	)
	if err != nil {
		log.Debugf("parse jwt error: %s", err)
		return nil, err
	}
	claims, ok := t.Claims.(*Token)
	if !ok || !t.Valid {
		return nil, errors.New("invalid token claims")
	}
	if claims.Username == "" {
		return nil, errors.New("token missing username claim")
	}
	return claims, nil
}
