package central

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Server 提供 API 與唯一的後台頁面。
type Server struct {
	svc     *Service
	mux     *http.ServeMux
	limiter *loginLimiter
	oidc    *oidcClient
}

// EnableOIDC 啟用 SSO 登入；必須在服務啟動前呼叫。
func (s *Server) EnableOIDC(cfg OIDCConfig) error {
	c, err := newOIDC(cfg)
	if err != nil {
		return err
	}
	s.oidc = c
	return nil
}

// NewServer 建立路由。
func NewServer(svc *Service) *Server {
	s := &Server{svc: svc, mux: http.NewServeMux(), limiter: newLoginLimiter()}
	s.routes()
	return s
}

// Handler 回傳 http.Handler。
func (s *Server) Handler() http.Handler { return s.mux }

// NewTLSConfig 建立 mTLS 設定：驗證用戶端憑證（若有提供）。
func NewTLSConfig(caPEM []byte) (*tls.Config, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("CA 憑證無效")
	}
	return &tls.Config{
		ClientCAs:  pool,
		ClientAuth: tls.VerifyClientCertIfGiven,
		MinVersion: tls.VersionTLS12,
	}, nil
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.HandleFunc("GET /metrics", s.handleMetrics)

	s.mux.HandleFunc("GET /api/v1/sync", s.auth(s.handleSync))
	s.mux.HandleFunc("POST /api/v1/self/private-key", s.auth(s.handlePrivateKey))

	s.mux.HandleFunc("GET /api/v1/admin/systems", s.admin(s.handleAdminList))
	s.mux.HandleFunc("POST /api/v1/admin/systems", s.admin(s.handleAdminCreate))
	s.mux.HandleFunc("PUT /api/v1/admin/systems/{code}", s.admin(s.handleAdminUpdate))
	s.mux.HandleFunc("POST /api/v1/admin/systems/{code}/enable", s.admin(s.handleAdminEnable))
	s.mux.HandleFunc("POST /api/v1/admin/systems/{code}/disable", s.admin(s.handleAdminDisable))
	s.mux.HandleFunc("POST /api/v1/admin/systems/{code}/rotate", s.admin(s.handleAdminRotate))
	s.mux.HandleFunc("GET /api/v1/admin/audit", s.admin(s.handleAdminAudit))

	s.mux.HandleFunc("GET /admin", s.requireRole(RoleViewer, s.handleUI))
	s.mux.HandleFunc("POST /admin/systems", s.requireRole(RoleAdmin, s.handleUICreate))
	s.mux.HandleFunc("POST /admin/systems/{code}/toggle", s.requireRole(RoleOperator, s.handleUIToggle))
	s.mux.HandleFunc("POST /admin/systems/{code}/rotate", s.requireRole(RoleOperator, s.handleUIRotate))
	s.mux.HandleFunc("GET /login", s.handleLoginPage)
	s.mux.HandleFunc("POST /login", s.handleLoginSubmit)
	s.mux.HandleFunc("GET /auth/callback", s.handleOIDCCallback)
	s.mux.HandleFunc("POST /logout", s.handleLogout)
}

// systemFrom 取得 mTLS 憑證上的系統代碼（CN）。
func systemFrom(r *http.Request) (string, bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", false
	}
	cn := strings.TrimSpace(r.TLS.PeerCertificates[0].Subject.CommonName)
	return cn, cn != ""
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		code, ok := systemFrom(r)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "缺少用戶端憑證")
			return
		}
		if !s.svc.CheckIP(code, r.RemoteAddr) {
			writeErr(w, http.StatusForbidden, "來源 IP 不符")
			return
		}
		next(w, r.WithContext(withSystem(r.Context(), code)))
	}
}

func (s *Server) apiToken() string {
	if s.svc.cfg.APIAdminToken != "" {
		return s.svc.cfg.APIAdminToken
	}
	return s.svc.cfg.AdminToken
}

// admin 保護管理 API：X-Admin-Token 或 Bearer，並限制來源網段。
func (s *Server) admin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.allowedAdminIP(r) {
			writeErr(w, http.StatusForbidden, "來源位址不在允許範圍")
			return
		}
		tok := r.Header.Get("X-Admin-Token")
		if tok == "" {
			tok = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		}
		want := s.apiToken()
		if want == "" || subtle.ConstantTimeCompare([]byte(tok), []byte(want)) != 1 {
			s.countAuthFailure()
			writeErr(w, http.StatusUnauthorized, "管理權杖無效")
			return
		}
		next(w, r)
	}
}

const (
	sessionCookieName = "cms_admin"
	sessionTTL        = 8 * time.Hour
)

// loginLimiter 限制單一來源的登入失敗次數，避免暴力猜測。
type loginLimiter struct {
	mu    sync.Mutex
	fails map[string]*loginBucket
}

type loginBucket struct {
	count int
	until time.Time
}

const (
	loginMaxFails = 5
	loginWindow   = 5 * time.Minute
)

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{fails: map[string]*loginBucket{}}
}

func (l *loginLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.fails[ip]
	if !ok {
		return true
	}
	if time.Now().After(b.until) {
		delete(l.fails, ip)
		return true
	}
	return b.count < loginMaxFails
}

func (l *loginLimiter) fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.fails[ip]
	if !ok || time.Now().After(b.until) {
		l.fails[ip] = &loginBucket{count: 1, until: time.Now().Add(loginWindow)}
		return
	}
	b.count++
}

func (l *loginLimiter) reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, ip)
}

// ctxPrincipal 存放目前操作者。
const ctxPrincipal ctxKey = "principal"

// requireRole 驗證工作階段與權限；POST 另驗 CSRF。
func (s *Server) requireRole(min Role, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.allowedAdminIP(r) {
			http.Error(w, "來源位址不在允許範圍", http.StatusForbidden)
			return
		}
		sd, val, ok := s.readSession(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if sd.Role < min {
			http.Error(w, "權限不足："+sd.Role.String()+" 無法執行此操作", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil {
				http.Error(w, "請求格式錯誤", http.StatusBadRequest)
				return
			}
			if subtle.ConstantTimeCompare([]byte(r.FormValue("csrf")), []byte(s.csrfFor(val))) != 1 {
				http.Error(w, "CSRF 驗證失敗，請重新整理頁面", http.StatusForbidden)
				return
			}
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxPrincipal, sd)))
	}
}

func principalFrom(r *http.Request) *sessionData {
	if v, ok := r.Context().Value(ctxPrincipal).(*sessionData); ok {
		return v
	}
	return &sessionData{User: "unknown", Role: RoleViewer}
}

func (s *Server) adminUser() string {
	if s.svc.cfg.AdminUser != "" {
		return s.svc.cfg.AdminUser
	}
	return "admin"
}

func (s *Server) countAuthFailure() {
	s.svc.mu.Lock()
	s.svc.counters.AuthFailure++
	s.svc.mu.Unlock()
}

func (s *Server) renderLogin(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = loginTemplate.Execute(w, map[string]any{
		"User":  s.adminUser(),
		"Error": msg,
		"SSO":   s.oidc != nil,
	})
}

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := s.readSession(r); ok {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	if s.oidc != nil {
		u, err := s.oidc.authURL()
		if err != nil {
			http.Error(w, "無法發起 SSO 登入："+err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, u, http.StatusSeeOther)
		return
	}
	s.renderLogin(w, http.StatusOK, "")
}

func (s *Server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if s.oidc != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	ip := clientIP(r)
	if !s.limiter.allow(ip) {
		s.renderLogin(w, http.StatusTooManyRequests, "嘗試次數過多，請 5 分鐘後再試")
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "請求格式錯誤", http.StatusBadRequest)
		return
	}
	user := r.FormValue("user")
	pass := r.FormValue("pass")
	okUser := subtle.ConstantTimeCompare([]byte(user), []byte(s.adminUser())) == 1
	okPass := subtle.ConstantTimeCompare([]byte(pass), []byte(s.svc.cfg.AdminToken)) == 1
	if !okUser || !okPass {
		s.limiter.fail(ip)
		s.countAuthFailure()
		s.renderLogin(w, http.StatusUnauthorized, "帳號或密碼錯誤")
		return
	}
	s.limiter.reset(ip)
	s.issueSession(w, user, RoleAdmin)
	s.svc.AuditLogin(user, "password", clientIP(r), "ok")
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

// handleOIDCCallback 處理 SSO 回呼：換 token、驗章、建立工作階段。
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		http.NotFound(w, r)
		return
	}
	if e := r.URL.Query().Get("error"); e != "" {
		s.renderLogin(w, http.StatusUnauthorized, "SSO 登入失敗："+e)
		return
	}
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		s.renderLogin(w, http.StatusBadRequest, "SSO 回呼缺少參數")
		return
	}
	claims, err := s.oidc.exchange(r.Context(), code, state)
	if err != nil {
		s.renderLogin(w, http.StatusUnauthorized, "SSO 驗證失敗："+err.Error())
		return
	}
	p := s.oidc.principalFromClaims(claims)
	if p.Role < RoleViewer {
		s.renderLogin(w, http.StatusForbidden, "此帳號未具備後台權限")
		return
	}
	s.issueSession(w, p.User, p.Role)
	s.svc.AuditLogin(p.User, "oidc", clientIP(r), "ok")
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if sd, _, ok := s.readSession(r); ok {
		s.svc.AuditLogin(sd.User, "logout", clientIP(r), "ok")
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: "", Path: "/", HttpOnly: true, Secure: true, MaxAge: -1,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "store": s.svc.StoreInfo()})
}

func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	c, total, enabled := s.svc.Metrics()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# TYPE key_sync_total counter\nkey_sync_total %d\n", c.SyncOK)
	fmt.Fprintf(w, "# TYPE key_sync_not_modified_total counter\nkey_sync_not_modified_total %d\n", c.SyncNotMod)
	fmt.Fprintf(w, "# TYPE key_sync_denied_total counter\nkey_sync_denied_total %d\n", c.SyncDenied)
	fmt.Fprintf(w, "# TYPE key_private_key_issued_total counter\nkey_private_key_issued_total %d\n", c.PrivIssued)
	fmt.Fprintf(w, "# TYPE key_private_key_denied_total counter\nkey_private_key_denied_total %d\n", c.PrivDenied)
	fmt.Fprintf(w, "# TYPE key_rotation_total counter\nkey_rotation_total %d\n", c.Rotations)
	fmt.Fprintf(w, "# TYPE key_admin_auth_failure_total counter\nkey_admin_auth_failure_total %d\n", c.AuthFailure)
	fmt.Fprintf(w, "# TYPE key_systems_total gauge\nkey_systems_total %d\n", total)
	fmt.Fprintf(w, "# TYPE key_systems_enabled gauge\nkey_systems_enabled %d\n", enabled)
}

// SyncResponse 是 /sync 的線上格式（與 SDK 規格一致：self／peers 巢狀）。
type SyncResponse struct {
	ServerTime string `json:"server_time"`
	Self       struct {
		SystemCode      string       `json:"system_code"`
		Encryption      PolicyView   `json:"encryption"`
		DecryptVersions []VersionRef `json:"decrypt_versions"`
	} `json:"self"`
	Peers map[string]VersionRef `json:"peers"`
}

// PolicyView 描述加密政策。
type PolicyView struct {
	Mode      string `json:"mode"`
	PolicyID  string `json:"policy_id,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Signature string `json:"signature,omitempty"`
}

func toWire(s *SyncSnapshot) SyncResponse {
	var out SyncResponse
	out.ServerTime = s.ServerTime.UTC().Format(time.RFC3339)
	out.Self.SystemCode = s.SystemCode
	out.Self.Encryption = PolicyView{Mode: s.Mode, PolicyID: s.PolicyID, ExpiresAt: s.PolicyExpiresAt, Signature: s.PolicySignature}
	out.Self.DecryptVersions = s.DecryptVersions
	out.Peers = s.Peers
	return out
}
func (s *Server) handleSync(w http.ResponseWriter, r *http.Request) {
	code := systemFromCtx(r)
	s.svc.Tick(time.Now())
	snap, err := s.svc.Sync(code)
	if err != nil {
		s.svc.mu.Lock()
		s.svc.counters.SyncDenied++
		s.svc.mu.Unlock()
		writeErr(w, http.StatusForbidden, "未登記或已停用")
		return
	}
	body, err := json.Marshal(toWire(snap))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "序列化失敗")
		return
	}
	etag := fmt.Sprintf(`W/"%x"`, sha256.Sum256(body))
	if r.Header.Get("If-None-Match") == etag {
		s.svc.mu.Lock()
		s.svc.counters.SyncNotMod++
		s.svc.mu.Unlock()
		w.WriteHeader(http.StatusNotModified)
		return
	}
	s.svc.mu.Lock()
	s.svc.counters.SyncOK++
	s.svc.mu.Unlock()
	w.Header().Set("ETag", etag)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

func (s *Server) handlePrivateKey(w http.ResponseWriter, r *http.Request) {
	code := systemFromCtx(r)
	var req struct {
		KID string `json:"kid"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil || req.KID == "" {
		writeErr(w, http.StatusBadRequest, "缺少 kid")
		return
	}
	der, err := s.svc.PrivateKey(code, req.KID)
	if err != nil {
		s.svc.mu.Lock()
		s.svc.counters.PrivDenied++
		s.svc.mu.Unlock()
		switch {
		case errors.Is(err, ErrForbidden):
			writeErr(w, http.StatusForbidden, "無權取得該版本私鑰")
		case errors.Is(err, ErrNotFound):
			writeErr(w, http.StatusNotFound, "版本不存在")
		default:
			writeErr(w, http.StatusInternalServerError, "取得私鑰失敗")
		}
		return
	}
	s.svc.mu.Lock()
	s.svc.counters.PrivIssued++
	s.svc.mu.Unlock()
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]string{
		"kid":             req.KID,
		"alg":             "ECIES-P256-AES256GCM",
		"private_key_b64": base64.StdEncoding.EncodeToString(der),
	})
}

func (s *Server) handleAdminList(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"systems": s.svc.Systems()})
}

func (s *Server) handleAdminCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code    string   `json:"code"`
		Name    string   `json:"name"`
		IPAllow []string `json:"ip_allow"`
		Note    string   `json:"note"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "請求格式錯誤")
		return
	}
	sys, err := s.svc.Register(req.Code, req.Name, req.IPAllow, req.Note, "admin", r.RemoteAddr)
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, sys)
}

func (s *Server) handleAdminUpdate(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	var req struct {
		Name    string   `json:"name"`
		IPAllow []string `json:"ip_allow"`
		Note    string   `json:"note"`
		Mode    string   `json:"mode"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "請求格式錯誤")
		return
	}
	sys, err := s.svc.UpdateSystem(code, req.Name, req.IPAllow, req.Note, req.Mode, "admin", r.RemoteAddr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, sys)
}

func (s *Server) handleAdminEnable(w http.ResponseWriter, r *http.Request) {
	s.toggle(w, r, true)
}

func (s *Server) handleAdminDisable(w http.ResponseWriter, r *http.Request) {
	s.toggle(w, r, false)
}

func (s *Server) toggle(w http.ResponseWriter, r *http.Request, enabled bool) {
	code := r.PathValue("code")
	if err := s.svc.SetStatus(code, enabled, "admin", r.RemoteAddr); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"code": code, "enabled": enabled})
}

func (s *Server) handleAdminRotate(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	v, err := s.svc.Rotate(code, "admin", r.RemoteAddr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleAdminAudit(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"entries": s.svc.Audit(200)})
}

// ---------- 後台唯一頁面 ----------

var loginTemplate = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html lang="zh-Hant"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>登入｜中央 KEY 管理服務</title>
<style>
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0f1b2d;
  font:15px/1.7 system-ui,-apple-system,'Microsoft JhengHei',sans-serif;color:#15243b}
.card{width:360px;background:#fff;border-radius:14px;padding:34px 30px 26px;box-shadow:0 24px 60px rgba(0,0,0,.35)}
.brand{font-size:12px;letter-spacing:.14em;color:#7b8aa3;text-transform:uppercase}
h1{font-size:23px;margin:6px 0 2px}
.sub{color:#63738a;font-size:13px;margin:0 0 22px}
label{display:block;font-size:13px;font-weight:600;margin-bottom:14px}
input{display:block;width:100%;margin-top:6px;padding:10px 12px;border:1px solid #cad6e7;border-radius:7px;font:inherit;background:#fbfcff}
input:focus{outline:2px solid #cfe0fa;border-color:#2459a8}
button{width:100%;padding:11px;border:0;border-radius:7px;background:#2459a8;color:#fff;font:inherit;font-weight:600;cursor:pointer}
button:hover{background:#1c4a8c}
.err{background:#fff1f0;border-left:3px solid #d9534f;color:#a33;padding:9px 12px;border-radius:5px;font-size:13px;margin-bottom:16px}
.hint{margin:18px 0 0;font-size:12px;color:#8a94a3}
code{background:#eef3fa;padding:1px 5px;border-radius:4px;font-size:12px}
</style></head><body>
<div class="card">
  <div class="brand">CMS Key Service</div>
  <h1>管理後台</h1>
  <p class="sub">系統登記與授權管理</p>
  {{if .Error}}<div class="err">{{.Error}}</div>{{end}}
  <form method="post" action="/login">
    <label>帳號<input name="user" value="{{.User}}" autocomplete="username" required autofocus></label>
    <label>密碼<input name="pass" type="password" autocomplete="current-password" required></label>
    <button type="submit">登入</button>
  </form>
  <p class="hint">密碼即啟動參數 <code>-admin-token</code> 的值，預設為 <code>dev-token</code>。</p>
</div>
</body></html>`))

var uiTemplate = template.Must(template.New("ui").Parse(`<!DOCTYPE html>
<html lang="zh-Hant"><head><meta charset="utf-8"><title>系統登記與授權管理</title>
<style>body{font:15px/1.7 system-ui,'Microsoft JhengHei',sans-serif;background:#f5f7fb;color:#15243b;margin:0}
main{max-width:960px;margin:28px auto;padding:0 20px 60px}.card{background:#fff;border:1px solid #dfe6ef;border-radius:10px;padding:22px;margin:16px 0}
h1{font-size:24px;margin:0 0 6px}.sub{color:#63738a;font-size:13px}
table{border-collapse:collapse;width:100%;font-size:14px}th,td{border-bottom:1px solid #dfe6ef;padding:9px 10px;text-align:left}
th{background:#f5f8fc}input,select{padding:7px 9px;border:1px solid #cad6e7;border-radius:5px;font:inherit}
button{padding:6px 12px;border:1px solid #cad6e7;background:#f8faff;border-radius:5px;cursor:pointer}
.on{color:#1a7f45;font-weight:700}.off{color:#8a94a3}.tag{background:#eaf1fc;color:#2459a8;padding:2px 8px;border-radius:4px;font-size:12px}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:end}
.toast{position:fixed;top:22px;right:22px;z-index:50;max-width:400px;padding:13px 18px 13px 16px;border-radius:9px;
 font-size:14px;background:#fff;color:#15243b;border-left:4px solid #2e8b57;
 box-shadow:0 12px 34px rgba(15,27,45,.18);animation:toastIn .22s ease-out,toastOut .4s ease-in 3.6s forwards}
.toast.err{border-left-color:#d9534f}
.toast .ico{font-weight:700;margin-right:8px;color:#2e8b57}
.toast.err .ico{color:#d9534f}
@keyframes toastIn{from{opacity:0;transform:translateY(-10px)}to{opacity:1;transform:none}}
@keyframes toastOut{to{opacity:0;transform:translateY(-10px);visibility:hidden}}
</style></head><body><main>
{{if .Toast}}<div class="toast {{.Toast.Kind}}" role="status"><span class="ico">{{if eq .Toast.Kind "err"}}!{{else}}✓{{end}}</span>{{.Toast.Text}}</div><script>history.replaceState(null,"","/admin")</script>{{end}}
<div class="card"><div style="float:right;text-align:right;font-size:13px"><b>{{.User}}</b> <span class="tag">{{.Role}}</span><form method="post" action="/logout" style="margin-top:6px"><input type="hidden" name="csrf" value="{{.CSRF}}"><button type="submit">登出</button></form></div><h1>系統登記與授權管理</h1>
<div class="sub">唯一後台頁面。停用即作廢該系統現行金鑰並於重新啟用時換鑰（決策 D2）。</div>
<table><tr><th>系統代碼</th><th>名稱</th><th>允許 IP</th><th>狀態</th><th>政策</th><th>操作</th></tr>
{{range .Systems}}<tr><td><b>{{.Code}}</b></td><td>{{.Name}}</td><td>{{range .IPAllow}}{{.}} {{end}}{{if eq (len .IPAllow) 0}}<span class="off">未設定</span>{{end}}</td>
<td>{{if eq .Status "enabled"}}<span class="on">啟用</span>{{else}}<span class="off">停用</span>{{end}}</td>
<td><span class="tag">{{.Mode}}</span></td>
<td>{{if $.CanWrite}}<form method="post" action="/admin/systems/{{.Code}}/toggle" style="display:inline"><input type="hidden" name="csrf" value="{{$.CSRF}}"><button type="submit">{{if eq .Status "enabled"}}停用{{else}}啟用{{end}}</button></form>
<form method="post" action="/admin/systems/{{.Code}}/rotate" style="display:inline"><input type="hidden" name="csrf" value="{{$.CSRF}}"><button type="submit">立即輪替</button></form>{{else}}<span class="off">唯讀</span>{{end}}</td></tr>
{{end}}</table></div>
{{if .CanAdmin}}<div class="card"><h3 style="margin-top:0">新增系統</h3>
<form method="post" action="/admin/systems"><input type="hidden" name="csrf" value="{{.CSRF}}"><div class="row">
<input name="code" placeholder="系統代碼（如 SYS-D）" required>
<input name="name" placeholder="系統名稱" required>
<input name="ip_allow" placeholder="允許 IP（空白分隔，可留空）" size="30">
<input name="note" placeholder="備註（選填）">
<button type="submit">建立並產生金鑰</button></div></form>
<div class="sub" style="margin-top:10px">建立後即自動產生金鑰對；私鑰由中央保管，系統經授權後取得自身私鑰。</div></div>{{end}}
</main></body></html>`))

// toast 是操作結果提示；Kind 為 "ok" 或 "err"。
type toast struct {
	Kind string
	Text string
}

// flash 依查詢參數組出提示訊息，避免 handler 直接拼 HTML。
func flash(r *http.Request) *toast {
	msg := r.URL.Query().Get("msg")
	name := r.URL.Query().Get("name")
	detail := r.URL.Query().Get("detail")
	switch msg {
	case "created":
		return &toast{"ok", fmt.Sprintf("已建立系統 %s，並自動產生一組金鑰", name)}
	case "enabled":
		return &toast{"ok", fmt.Sprintf("已啟用 %s，並產生全新金鑰", name)}
	case "disabled":
		return &toast{"ok", fmt.Sprintf("已停用 %s，現行金鑰已作廢", name)}
	case "rotated":
		return &toast{"ok", fmt.Sprintf("已輪替 %s，舊版金鑰將於 5 分鐘後退役", name)}
	case "error":
		if detail == "" {
			detail = "請稍後再試"
		}
		return &toast{"err", "操作失敗：" + detail}
	}
	return nil
}

// redirectFlash 以 PRG 模式帶提示訊息回首頁。
func redirectFlash(w http.ResponseWriter, r *http.Request, msg, name string) {
	u := "/admin?msg=" + url.QueryEscape(msg)
	if name != "" {
		u += "&name=" + url.QueryEscape(name)
	}
	http.Redirect(w, r, u, http.StatusSeeOther)
}

// redirectFlashErr 把錯誤訊息（截斷後）帶回首頁顯示為紅色提示。
func redirectFlashErr(w http.ResponseWriter, r *http.Request, err error) {
	detail := strings.TrimPrefix(err.Error(), "conflict: ")
	detail = strings.TrimPrefix(detail, "not found: ")
	detail = strings.TrimPrefix(detail, "forbidden: ")
	detail = strings.TrimPrefix(detail, "unavailable: ")
	if rs := []rune(detail); len(rs) > 90 {
		detail = string(rs[:90]) + "…"
	}
	u := "/admin?msg=error&detail=" + url.QueryEscape(detail)
	http.Redirect(w, r, u, http.StatusSeeOther)
}

func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	sd, val, _ := s.readSession(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = uiTemplate.Execute(w, map[string]any{
		"Systems":  s.svc.Systems(),
		"Toast":    flash(r),
		"User":     sd.User,
		"Role":     sd.Role.String(),
		"CSRF":     s.csrfFor(val),
		"CanWrite": sd.Role >= RoleOperator,
		"CanAdmin": sd.Role >= RoleAdmin,
	})
}

func (s *Server) handleUICreate(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	code := strings.TrimSpace(r.FormValue("code"))
	name := strings.TrimSpace(r.FormValue("name"))
	note := strings.TrimSpace(r.FormValue("note"))
	var ips []string
	for _, f := range strings.Fields(r.FormValue("ip_allow")) {
		ips = append(ips, f)
	}
	if _, err := s.svc.Register(code, name, ips, note, principalFrom(r).User, r.RemoteAddr); err != nil {
		redirectFlashErr(w, r, err)
		return
	}
	redirectFlash(w, r, "created", code)
}

func (s *Server) handleUIToggle(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	var enabled bool
	for _, sys := range s.svc.Systems() {
		if sys.Code == code {
			enabled = sys.Status != StatusEnabled
		}
	}
	if err := s.svc.SetStatus(code, enabled, principalFrom(r).User, r.RemoteAddr); err != nil {
		redirectFlashErr(w, r, err)
		return
	}
	if enabled {
		redirectFlash(w, r, "enabled", code)
		return
	}
	redirectFlash(w, r, "disabled", code)
}

func (s *Server) handleUIRotate(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	if _, err := s.svc.Rotate(code, principalFrom(r).User, r.RemoteAddr); err != nil {
		redirectFlashErr(w, r, err)
		return
	}
	redirectFlash(w, r, "rotated", code)
}

// ---------- 小工具 ----------

type ctxKey string

const ctxSystem ctxKey = "system"

func withSystem(ctx context.Context, code string) context.Context {
	return context.WithValue(ctx, ctxSystem, code)
}

func systemFromCtx(r *http.Request) string {
	if v, ok := r.Context().Value(ctxSystem).(string); ok {
		return v
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
