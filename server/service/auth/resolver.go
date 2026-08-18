package auth

import (
	"time"

	"NanoKVM-Server/config"
	"NanoKVM-Server/middleware"
	"NanoKVM-Server/service/wsguard"
)

// init wires the auth store into the JWT middleware and the WebSocket guard.
// Both use function hooks (not direct imports) because the middleware and
// wsguard packages must not import auth, which would create an import cycle:
// auth already imports middleware for GenerateJWT.
func init() {
	// Per-request live validation of a token against current account state.
	middleware.AccountResolver = func(username string) (string, int, bool, error) {
		acc, err := GetAccountByUsername(username)
		if err != nil {
			return "", 0, false, err
		}
		return string(acc.Role), acc.TokenVersion, acc.Enabled, nil
	}

	// Snapshot of all accounts for the WebSocket watchdog. Returns (nil, nil)
	// when authentication is disabled so the watchdog enforces nothing.
	wsguard.AccountsSnapshot = func() (map[string]wsguard.State, error) {
		if config.GetInstance().Authentication == "disable" {
			return nil, nil
		}
		accounts, err := GetAccounts()
		if err != nil {
			return nil, err
		}
		m := make(map[string]wsguard.State, len(accounts))
		for _, a := range accounts {
			m[a.Username] = wsguard.State{Version: a.TokenVersion, Enabled: a.Enabled}
		}
		return m, nil
	}

	// Tear down live connections shortly after a session is revoked/disabled,
	// rather than only blocking new connections at handshake.
	wsguard.StartWatchdog(3 * time.Second)
}
