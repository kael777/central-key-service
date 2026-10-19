package central_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"example.com/key-sdk/central"
)

// mockIdP 是最小的 OIDC Provider，用來驗證授權碼流程與 id_token 驗章。
type mockIdP struct {
	t      *testing.T
	key    *rsa.PrivateKey
	server *httptest.Server
	nonces map[string]string
	mu     sync.Mutex
	groups []string
	user   string
}

func newMockIdP(t *testing.T) *mockIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("產生 RSA 金鑰失敗：%v", err)
	}
	m := &mockIdP{
		t:      t,
		key:    key,
		nonces: map[string]string{},
		groups: []string{"cms-admins"},
		user:   "alice",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 m.server.URL,
			"authorization_endpoint": m.server.URL + "/authorize",
			"token_endpoint":         m.server.URL + "/token",
			"jwks_uri":               m.server.URL + "/jwks",
		})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		code := "code-" + r.URL.Query().Get("state")
		m.mu.Lock()
		m.nonces[code] = r.URL.Query().Get("nonce")
		m.mu.Unlock()
		redirect := r.URL.Query().Get("redirect_uri")
		sep := "?"
		if strings.Contains(redirect, "?") {
			sep = "&"
		}
		http.Redirect(w, r, redirect+sep+"code="+code+"&state="+r.URL.Query().Get("state"), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		code := r.FormValue("code")
		m.mu.Lock()
		nonce := m.nonces[code]
		m.mu.Unlock()
		claims := map[string]any{
			"iss":                m.server.URL,
			"aud":                "test-client",
			"sub":                "user-1",
			"exp":                time.Now().Add(time.Hour).Unix(),
			"nonce":              nonce,
			"preferred_username": m.user,
			"groups":             m.groups,
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": m.signJWT(claims)})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA",
				"kid": "test-key",
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(m.key.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(m.key.E)).Bytes()),
			}},
		})
	})
	m.server = httptest.NewServer(mux)
	t.Cleanup(m.server.Close)
	return m
}

func (m *mockIdP) signJWT(claims map[string]any) string {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "test-key", "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	signing := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, m.key, crypto.SHA256, sum[:])
	if err != nil {
		m.t.Fatalf("簽章失敗：%v", err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// newOIDCEnv 建立「中央服務 + 假 IdP」的測試環境。
func newOIDCEnv(t *testing.T, groups []string, defaultRole central.Role, mapping map[string]central.Role) (string, *http.Client) {
	t.Helper()
	idp := newMockIdP(t)
	idp.groups = groups

	ca, err := central.GenerateCA("CMS", "CMS Test CA")
	if err != nil {
		t.Fatalf("CA 失敗：%v", err)
	}
	pool, err := ca.Pool()
	if err != nil {
		t.Fatalf("憑證池失敗：%v", err)
	}
	serverCert, serverKey, err := ca.IssueServer([]string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatalf("伺服器憑證失敗：%v", err)
	}
	pair, err := tls.X509KeyPair(serverCert, serverKey)
	if err != nil {
		t.Fatalf("載入憑證失敗：%v", err)
	}

	svc := central.NewService(central.Config{
		KEK:        make([]byte, 32),
		AdminToken: "test-token",
		Grace:      time.Minute,
	})
	s := central.NewServer(svc)
	srv := httptest.NewUnstartedServer(s.Handler())
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	if err := s.EnableOIDC(central.OIDCConfig{
		Issuer:        idp.server.URL,
		ClientID:      "test-client",
		RedirectURL:   srv.URL + "/auth/callback",
		GroupRoles:    mapping,
		DefaultRole:   defaultRole,
		GroupsClaim:   "groups",
		UsernameClaim: "preferred_username",
	}); err != nil {
		t.Fatalf("啟用 OIDC 失敗：%v", err)
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar:       jar,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
	}
	return srv.URL, client
}

func TestOIDCLoginAndRole(t *testing.T) {
	mapping := map[string]central.Role{
		"cms-admins":  central.RoleAdmin,
		"cms-ops":     central.RoleOperator,
		"cms-viewers": central.RoleViewer,
	}
	base, client := newOIDCEnv(t, []string{"cms-admins"}, central.RoleViewer, mapping)

	// /login 應導向 IdP，最終回到 /admin
	resp, err := client.Get(base + "/login")
	if err != nil {
		t.Fatalf("登入流程失敗：%v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("登入後應為 200，實際 %d：%s", resp.StatusCode, string(body))
	}
	if !strings.Contains(string(body), "alice") {
		t.Fatalf("頁面未顯示登入使用者：%s", string(body)[:200])
	}
	if !strings.Contains(string(body), "admin") {
		t.Fatal("角色應為 admin")
	}
}

func TestOIDCViewerCannotWrite(t *testing.T) {
	base, client := newOIDCEnv(t, []string{"cms-viewers"}, central.RoleViewer,
		map[string]central.Role{"cms-viewers": central.RoleViewer})

	resp, err := client.Get(base + "/login")
	if err != nil {
		t.Fatalf("登入失敗：%v", err)
	}
	resp.Body.Close()

	// viewer 不應看到新增表單
	resp, err = client.Get(base + "/admin")
	if err != nil {
		t.Fatalf("讀取後台失敗：%v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.Contains(string(body), `action="/admin/systems"`) {
		t.Fatal("viewer 不應看到新增系統表單")
	}

	// viewer 直接 POST 也應被拒
	form := strings.NewReader("code=SYS-X&name=x")
	req, _ := http.NewRequest(http.MethodPost, base+"/admin/systems", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("POST 失敗：%v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer 新增應為 403，實際 %d", resp.StatusCode)
	}
}
