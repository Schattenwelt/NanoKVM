package auth

import (
	"net/http"
	"strings"
	"time"

	"NanoKVM-Server/config"
	"NanoKVM-Server/middleware"
	"NanoKVM-Server/proto"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

const (
	authCookieName = "nano-kvm-token"
	authFlagName   = "nano-kvm-auth"
)

// requestIsTLS reports whether the request reached us over HTTPS, directly or
// via a TLS-terminating reverse proxy. The Secure cookie flag is only set when
// true, otherwise a plain-HTTP LAN client would never receive the cookie.
func requestIsTLS(c *gin.Context) bool {
	if c.Request.TLS != nil {
		return true
	}
	return strings.EqualFold(c.GetHeader("X-Forwarded-Proto"), "https")
}

// setAuthCookies stores the JWT in an HttpOnly, SameSite=Strict cookie (Secure
// under TLS) so it is never exposed to JavaScript / XSS. A second, non-secret
// flag cookie lets the frontend know a session exists without reading the token.
func setAuthCookies(c *gin.Context, token string) {
	maxAge := int(config.GetInstance().JWT.RefreshTokenDuration)
	secure := requestIsTLS(c)
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(authCookieName, token, maxAge, "/", "", secure, true)
	c.SetCookie(authFlagName, "1", maxAge, "/", "", secure, false)
}

// clearAuthCookies removes both cookies on logout.
func clearAuthCookies(c *gin.Context) {
	secure := requestIsTLS(c)
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(authCookieName, "", -1, "/", "", secure, true)
	c.SetCookie(authFlagName, "", -1, "/", "", secure, false)
}

func (s *Service) Login(c *gin.Context) {
	var req proto.LoginReq
	var rsp proto.Response

	conf := config.GetInstance()
	if conf.Authentication == "disable" {
		c.SetSameSite(http.SameSiteStrictMode)
		c.SetCookie(authFlagName, "1", int(conf.JWT.RefreshTokenDuration), "/", "", requestIsTLS(c), false)
		rsp.OkRspWithData(c, &proto.LoginRsp{Token: ""})
		return
	}

	clientIP := GetClientIP(c)
	if locked, code, msg := CheckLoginAttempt(clientIP); locked {
		time.Sleep(3 * time.Second)
		rsp.ErrRsp(c, code, msg)
		return
	}

	if err := proto.ParseFormRequest(c, &req); err != nil {
		time.Sleep(3 * time.Second)
		rsp.ErrRsp(c, -1, "invalid parameters")
		return
	}

	account, ok := CompareAccount(req.Username, req.Password)
	if !ok {
		c.Set("audit_user", req.Username)
		c.Set("audit_result", "failure")
		time.Sleep(2 * time.Second)
		if locked, code, msg := RecordLoginFailure(clientIP); locked {
			rsp.ErrRsp(c, code, msg)
			return
		}
		rsp.ErrRsp(c, -2, "invalid username or password")
		return
	}

	ClearLoginAttempt(clientIP)

	token, err := middleware.GenerateJWT(account.Username, string(account.Role), account.TokenVersion)
	if err != nil {
		time.Sleep(1 * time.Second)
		rsp.ErrRsp(c, -3, "generate token failed")
		return
	}

	setAuthCookies(c, token)
	rsp.OkRspWithData(c, &proto.LoginRsp{Token: ""})
	c.Set("audit_user", account.Username)
	c.Set("audit_role", string(account.Role))
	c.Set("audit_result", "success")
	log.Debugf("login success, username: %s, role: %s", account.Username, account.Role)
}

func (s *Service) Logout(c *gin.Context) {
	var rsp proto.Response
	// Revoke only THIS user's sessions by bumping their token version, instead of
	// regenerating the global secret key (which logged out every NanoKVM user).
	if v, ok := c.Get("username"); ok {
		if username, ok2 := v.(string); ok2 && username != "" {
			if err := BumpTokenVersion(username); err != nil {
				log.Warnf("logout: failed to revoke sessions for %s: %s", username, err)
			}
		}
	}
	clearAuthCookies(c)
	rsp.OkRsp(c)
}

func (s *Service) GetAccount(c *gin.Context) {
	var rsp proto.Response

	username, _ := c.Get("username")
	role, _ := c.Get("role")

	rsp.OkRspWithData(c, &proto.GetAccountRsp{
		Username: username.(string),
		Role:     role.(string),
	})
	log.Debugf("get account successful")
}
