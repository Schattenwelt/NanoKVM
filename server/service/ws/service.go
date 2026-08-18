package ws

import (
	"NanoKVM-Server/service/wsguard"
	"NanoKVM-Server/utils"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

type Service struct{}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     utils.IsSameOrigin,
}

func NewService() *Service {
	return &Service{}
}

func (s *Service) Connect(c *gin.Context) {
	ws, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Errorf("create websocket failed: %s", err)
		return
	}

	log.Debug("websocket connected")

	if unregister := wsguard.RegisterFromContext(c, ws); unregister != nil {
		defer unregister()
	}

	client := NewClient(ws)

	manager := GetManager()
	manager.AddClient(ws, client)
	defer manager.RemoveClient(ws)

	sendCaptureStatusSnapshot(client)
	sendH264ModeStatusSnapshot(client)
	sendKeyboardLedStatusSnapshot(client)

	client.Start()
}
