package central

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// Role 是後台權限等級，數字越大權限越高。
type Role int

const (
	RoleViewer   Role = 1 // 只能看列表
	RoleOperator Role = 2 // 啟用／停用／輪替
	RoleAdmin    Role = 3 // 新增／修改系統
)

func (r Role) String() string {
	switch r {
	case RoleViewer:
		return "viewer"
	case RoleOperator:
		return "operator"
	case RoleAdmin:
		return "admin"
	}
	return "unknown"
}

func ParseRole(s string) Role {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "viewer", "readonly", "read-only":
		return RoleViewer
	case "operator", "ops":
		return RoleOperator
	case "admin", "administrator":
		return RoleAdmin
	}
	return 0
}

// Principal 是已驗證的操作者。
type Principal struct {
	User string
	Role Role
}

// session 內容：使用者、角色、到期時間；以管理權杖簽章。
type sessionData struct {
	User string `json:"u"`
	Role Role   `json:"r"`
	Exp  int64  `json:"e"`
}

func (s *Server) sessionKey() []byte {
	secret := s.svc.cfg.SessionSecret
	if secret == "" {
		secret = s.svc.cfg.AdminToken
	}
	return []byte("cms-admin-session|" + secret)
}

func (s *Server) sign(data []byte) string {
	mac := hmac.New(sha256.New, s.sessionKey())
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

// issueSession 寫入簽章 cookie；payload 為使用者與角色。
func (s *Server) issueSession(w http.ResponseWriter, user string, role Role) {
	sd := sessionData{User: user, Role: role, Exp: time.Now().Add(sessionTTL).Unix()}
	raw, _ := json.Marshal(sd)
	payload := base64.RawURLEncoding.EncodeToString(raw)
	value := payload + "." + s.sign([]byte(payload))
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
}

func (s *Server) readSession(r *http.Request) (*sessionData, string, bool) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, "", false
	}
	payload, sig, ok := strings.Cut(c.Value, ".")
	if !ok {
		return nil, "", false
	}
	if !hmac.Equal([]byte(sig), []byte(s.sign([]byte(payload)))) {
		return nil, "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, "", false
	}
	var sd sessionData
	if err := json.Unmarshal(raw, &sd); err != nil {
		return nil, "", false
	}
	if time.Now().Unix() > sd.Exp {
		return nil, "", false
	}
	return &sd, c.Value, true
}

// csrfFor 由目前 session 派生 CSRF token（雙重提交）。
func (s *Server) csrfFor(sessionValue string) string {
	mac := hmac.New(sha256.New, s.sessionKey())
	mac.Write([]byte("csrf|" + sessionValue))
	return hex.EncodeToString(mac.Sum(nil))
}

// randomToken 產生 URL 安全的隨機字串（state / nonce 用）。
func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// clientIP 取出來源 IP（去掉埠號）。
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// allowedAdminIP 檢查後台來源是否在允許網段；清單為空代表不限制。
func (s *Server) allowedAdminIP(r *http.Request) bool {
	cidrs := s.svc.cfg.AdminCIDR
	if len(cidrs) == 0 {
		return true
	}
	return HostAllowed(cidrs, r.RemoteAddr)
}

var _ = randomToken
