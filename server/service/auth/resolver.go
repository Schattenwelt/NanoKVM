package auth

import (
	"NanoKVM-Server/middleware"
)

// init wires the JWT middleware to the live account store. The middleware calls
// this on every authenticated request to verify the token against current role,
// token version and enabled state. It lives here (not in middleware) because the
// middleware package must not import auth: auth already imports middleware for
// GenerateJWT, and the reverse would create an import cycle.
func init() {
	middleware.AccountResolver = func(username string) (string, int, bool, error) {
		acc, err := GetAccountByUsername(username)
		if err != nil {
			return "", 0, false, err
		}
		return string(acc.Role), acc.TokenVersion, acc.Enabled, nil
	}
}
