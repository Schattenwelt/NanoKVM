package utils

import (
	"net/http"
	"net/url"
	"strings"
)

// IsSameOrigin reports whether a WebSocket upgrade request originates from the
// same host as the server. It is used as gorilla/websocket's CheckOrigin to
// prevent cross-site WebSocket hijacking (CSWSH).
//
// Requests without an Origin header (native / non-browser clients such as the
// mobile app) are allowed, because browsers always send Origin on WebSocket
// handshakes. Browser requests must have an Origin host matching the request
// Host; anything else (including the opaque "null" origin) is rejected.
func IsSameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}
