package wsguard

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

// closeCodeRevoked is the WebSocket close code sent when a live connection is
// terminated because the user's session was revoked, disabled, or deleted.
const closeCodeRevoked = 4401

// State is a snapshot of one account's revocation-relevant fields.
type State struct {
	Version int
	Enabled bool
}

// AccountsSnapshot is registered by the auth service at startup. It returns the
// current token version and enabled flag for every account. Returning
// (nil, nil) means enforcement is off (e.g. authentication disabled) and the
// watchdog leaves connections alone for that tick. It exists as a hook to avoid
// an import cycle with the auth package.
var AccountsSnapshot func() (map[string]State, error)

type conn struct {
	username string
	version  int
	ws       *websocket.Conn
	closed   int32
}

func (c *conn) revoke() {
	if !atomic.CompareAndSwapInt32(&c.closed, 0, 1) {
		return
	}
	// WriteControl and Close are safe to call concurrently with the handler's
	// own reads/writes; closing the socket unblocks the handler loop cleanly.
	msg := websocket.FormatCloseMessage(closeCodeRevoked, "session revoked")
	_ = c.ws.WriteControl(websocket.CloseMessage, msg, time.Now().Add(time.Second))
	_ = c.ws.Close()
}

var (
	mu    sync.Mutex
	conns = make(map[uint64]*conn)
	seq   uint64
)

// Register records an authenticated WebSocket so it can be force-closed later.
// The returned func must be deferred by the caller to unregister on disconnect.
func Register(username string, version int, ws *websocket.Conn) func() {
	mu.Lock()
	seq++
	id := seq
	conns[id] = &conn{username: username, version: version, ws: ws}
	mu.Unlock()
	return func() {
		mu.Lock()
		delete(conns, id)
		mu.Unlock()
	}
}

// RegisterFromContext registers a WebSocket opened by an authenticated request,
// reading the username and token version stored by the auth middleware. If no
// authenticated user is present (e.g. an internal loopback connection) it does
// nothing and returns nil.
func RegisterFromContext(c *gin.Context, ws *websocket.Conn) func() {
	username := c.GetString("username")
	if username == "" {
		return nil
	}
	return Register(username, c.GetInt("token_version"), ws)
}

// StartWatchdog launches a goroutine that periodically validates every
// registered connection against live account state and closes any whose user
// was deleted, disabled, or had their token version bumped (logout, password or
// role change). It also catches external changes such as a BOOT reset of the
// account file. Call once at startup.
func StartWatchdog(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			if AccountsSnapshot == nil {
				continue
			}
			snap, err := AccountsSnapshot()
			if err != nil || snap == nil {
				// Transient read error or enforcement disabled: never kill on a
				// transient failure; new connections are still checked at handshake.
				continue
			}
			mu.Lock()
			victims := make([]*conn, 0)
			for _, c := range conns {
				st, ok := snap[c.username]
				if !ok || !st.Enabled || st.Version != c.version {
					victims = append(victims, c)
				}
			}
			mu.Unlock()
			for _, c := range victims {
				log.Infof("wsguard: revoking live connection for %q (session no longer valid)", c.username)
				c.revoke()
			}
		}
	}()
}
