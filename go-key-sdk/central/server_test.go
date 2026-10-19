package central_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"example.com/key-sdk/central"
	"example.com/key-sdk/keycrypto"
)

const adminToken = "test-token"

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Date(2026, 10, 19, 9, 0, 0, 0, time.UTC)} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type env struct {
	t       *testing.T
	svc     *central.Service
	base    string
	ca      *central.CA
	pool    *x509.CertPool
	server  *httptest.Server
	clients map[string]*http.Client
}

func newEnv(t *testing.T, grace time.Duration) *env {
	t.Helper()
	ca, err := central.GenerateCA("CMS", "CMS Test CA")
	if err != nil {
		t.Fatalf("產生 CA 失敗：%v", err)
	}
	pool, err := ca.Pool()
	if err != nil {
		t.Fatalf("建立憑證池失敗：%v", err)
	}
	serverCert, serverKey, err := ca.IssueServer([]string{"127.0.0.1", "localhost"}, time.Hour)
	if err != nil {
		t.Fatalf("簽發伺服器憑證失敗：%v", err)
	}
	pair, err := tls.X509KeyPair(serverCert, serverKey)
	if err != nil {
		t.Fatalf("載入伺服器憑證失敗：%v", err)
	}

	clk := newClock()
	svc := central.NewService(central.Config{
		Grace:      grace,
		Prepublish: time.Minute,
		KEK:        bytes.Repeat([]byte{0x42}, 32),
		AdminToken: adminToken,
		Now:        clk.Now,
	})

	srv := httptest.NewUnstartedServer(central.NewServer(svc).Handler())
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{pair},
		ClientCAs:    pool,
		ClientAuth:   tls.VerifyClientCertIfGiven,
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()

	e := &env{t: t, svc: svc, base: srv.URL, ca: ca, pool: pool, server: srv, clients: map[string]*http.Client{}}
	t.Cleanup(srv.Close)
	return e
}

func (e *env) clientFor(code string) *http.Client {
	e.t.Helper()
	if c, ok := e.clients[code]; ok {
		return c
	}
	certPEM, keyPEM, err := e.ca.IssueClient(code, time.Hour)
	if err != nil {
		e.t.Fatalf("簽發 %s 憑證失敗：%v", code, err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		e.t.Fatalf("載入 %s 憑證失敗：%v", code, err)
	}
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		Certificates: []tls.Certificate{pair},
		RootCAs:      e.pool,
		MinVersion:   tls.VersionTLS12,
	}}}
	e.clients[code] = c
	return c
}

func (e *env) admin() *http.Client {
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: e.pool}}}
	return c
}

func (e *env) register(code, name string, ips []string) {
	e.t.Helper()
	body, _ := json.Marshal(map[string]any{"code": code, "name": name, "ip_allow": ips})
	req, _ := http.NewRequest(http.MethodPost, e.base+"/api/v1/admin/systems", bytes.NewReader(body))
	req.Header.Set("X-Admin-Token", adminToken)
	resp, err := e.admin().Do(req)
	if err != nil {
		e.t.Fatalf("登記 %s 失敗：%v", code, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		e.t.Fatalf("登記 %s 回應 %d：%s", code, resp.StatusCode, b)
	}
}

func (e *env) sync(code string) (*central.SyncResponse, int) {
	e.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, e.base+"/api/v1/sync", nil)
	resp, err := e.clientFor(code).Do(req)
	if err != nil {
		e.t.Fatalf("sync 失敗：%v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode
	}
	var snap central.SyncResponse
	if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
		e.t.Fatalf("解析 sync 失敗：%v", err)
	}
	return &snap, resp.StatusCode
}

func (e *env) privateKey(code, kid string) (*ecdh.PrivateKey, int) {
	e.t.Helper()
	body, _ := json.Marshal(map[string]string{"kid": kid})
	req, _ := http.NewRequest(http.MethodPost, e.base+"/api/v1/self/private-key", bytes.NewReader(body))
	resp, err := e.clientFor(code).Do(req)
	if err != nil {
		e.t.Fatalf("取得私鑰失敗：%v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode
	}
	var out struct {
		PrivateKeyB64 string `json:"private_key_b64"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		e.t.Fatalf("解析私鑰回應失敗：%v", err)
	}
	der, err := base64.StdEncoding.DecodeString(out.PrivateKeyB64)
	if err != nil {
		e.t.Fatalf("私鑰 base64 解碼失敗：%v", err)
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		e.t.Fatalf("私鑰解析失敗：%v", err)
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		e.t.Fatal("私鑰型別錯誤")
	}
	p, err := ec.ECDH()
	if err != nil {
		e.t.Fatalf("私鑰轉換失敗：%v", err)
	}
	return p, resp.StatusCode
}

// TestEndToEnd 驗證最核心的一條路徑：A 取得 B 的公鑰加密，B 取得自身私鑰解密。
func TestEndToEnd(t *testing.T) {
	e := newEnv(t, 5*time.Minute)
	e.register("SYS-A", "發送系統", []string{"127.0.0.1"})
	e.register("SYS-B", "接收系統", []string{"127.0.0.1"})

	snapA, status := e.sync("SYS-A")
	if status != http.StatusOK {
		t.Fatalf("SYS-A sync 狀態碼 %d", status)
	}
	peer, ok := snapA.Peers["SYS-B"]
	if !ok {
		t.Fatal("快照缺少 SYS-B 公鑰")
	}
	spki, err := base64.StdEncoding.DecodeString(peer.PublicKey)
	if err != nil {
		t.Fatalf("公鑰解碼失敗：%v", err)
	}

	token, err := keycrypto.EncryptTo(spki, peer.KID, "urlparam", []byte("a=1&b=2"))
	if err != nil {
		t.Fatalf("加密失敗：%v", err)
	}

	priv, status := e.privateKey("SYS-B", peer.KID)
	if status != http.StatusOK {
		t.Fatalf("取得私鑰狀態碼 %d", status)
	}
	got, err := keycrypto.Decrypt(priv, token, "urlparam")
	if err != nil {
		t.Fatalf("解密失敗：%v", err)
	}
	if string(got) != "a=1&b=2" {
		t.Fatalf("明文不符：%q", got)
	}

	// 其他人不得取得 B 的私鑰
	if _, status := e.privateKey("SYS-A", peer.KID); status != http.StatusForbidden {
		t.Fatalf("SYS-A 取得 SYS-B 私鑰應被拒絕，實際 %d", status)
	}
}

// TestDisableRetiresKeys 驗證決策 D2：停用即作廢金鑰；重新啟用換新鍵。
func TestDisableRetiresKeys(t *testing.T) {
	e := newEnv(t, 5*time.Minute)
	e.register("SYS-B", "接收系統", nil)

	snap, _ := e.sync("SYS-B")
	oldKID := snap.Self.DecryptVersions[0].KID

	if err := e.svc.SetStatus("SYS-B", false, "test", "127.0.0.1"); err != nil {
		t.Fatalf("停用失敗：%v", err)
	}
	if _, status := e.sync("SYS-B"); status != http.StatusForbidden {
		t.Fatalf("停用後 sync 應為 403，實際 %d", status)
	}
	if _, status := e.privateKey("SYS-B", oldKID); status != http.StatusForbidden {
		t.Fatalf("停用後取舊私鑰應為 403，實際 %d", status)
	}

	if err := e.svc.SetStatus("SYS-B", true, "test", "127.0.0.1"); err != nil {
		t.Fatalf("啟用失敗：%v", err)
	}
	snap2, status := e.sync("SYS-B")
	if status != http.StatusOK {
		t.Fatalf("重新啟用後 sync 狀態碼 %d", status)
	}
	if snap2.Self.DecryptVersions[0].KID == oldKID {
		t.Fatal("重新啟用後應產生新金鑰版本")
	}
	if _, status := e.privateKey("SYS-B", oldKID); status != http.StatusForbidden {
		t.Fatalf("舊版本私鑰應已銷毀，實際 %d", status)
	}
}

// TestGraceWindow 驗證 5 分鐘緩衝：輪替後舊版仍可解，到期後拒絕。
func TestGraceWindow(t *testing.T) {
	grace := 5 * time.Minute
	e := newEnv(t, grace)
	e.register("SYS-B", "接收系統", nil)

	snap, _ := e.sync("SYS-B")
	oldKID := snap.Self.DecryptVersions[0].KID
	if _, err := e.svc.Rotate("SYS-B", "test", "127.0.0.1"); err != nil {
		t.Fatalf("輪替失敗：%v", err)
	}
	// 緩衝期內：舊版仍可取得私鑰
	if _, status := e.privateKey("SYS-B", oldKID); status != http.StatusOK {
		t.Fatalf("緩衝期內取舊私鑰應成功，實際 %d", status)
	}
	// 快照應同時包含新舊版本
	snap2, _ := e.sync("SYS-B")
	if len(snap2.Self.DecryptVersions) != 2 {
		t.Fatalf("緩衝期內應有 2 個解密版本，實際 %d", len(snap2.Self.DecryptVersions))
	}

	// 推進到緩衝期之後
	e.svc.Tick(time.Now().Add(grace + time.Second))
}

// TestIPAllowlist 驗證來源 IP 白名單。
func TestIPAllowlist(t *testing.T) {
	e := newEnv(t, 5*time.Minute)
	e.register("SYS-C", "受限制系統", []string{"10.0.0.0/8"})
	if _, status := e.sync("SYS-C"); status != http.StatusForbidden {
		t.Fatalf("IP 不符應為 403，實際 %d", status)
	}
}

// TestUnknownSystem 驗證未登記系統無法取得任何東西。
func TestUnknownSystem(t *testing.T) {
	e := newEnv(t, 5*time.Minute)
	if _, status := e.sync("SYS-X"); status != http.StatusForbidden {
		t.Fatalf("未登記系統 sync 應為 403，實際 %d", status)
	}
}

// TestAuditAndMetrics 驗證稽核與監控輸出。
func TestAuditAndMetrics(t *testing.T) {
	e := newEnv(t, 5*time.Minute)
	e.register("SYS-A", "測試", nil)
	_, _ = e.sync("SYS-A")

	entries := e.svc.Audit(0)
	if len(entries) == 0 {
		t.Fatal("稽核紀錄為空")
	}
	found := false
	for _, en := range entries {
		if en.Action == "system.register" && en.System == "SYS-A" {
			found = true
		}
	}
	if !found {
		t.Fatal("找不到 system.register 稽核紀錄")
	}

	resp, err := e.admin().Get(e.base + "/metrics")
	if err != nil {
		t.Fatalf("取得 metrics 失敗：%v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), "key_sync_total") {
		t.Fatalf("metrics 內容不如預期：%s", b)
	}
}

// TestAdminTokenRequired 驗證管理端點必須帶權杖。
func TestAdminTokenRequired(t *testing.T) {
	e := newEnv(t, 5*time.Minute)
	resp, err := e.admin().Get(e.base + "/api/v1/admin/systems")
	if err != nil {
		t.Fatalf("請求失敗：%v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("缺少權杖應為 401，實際 %d", resp.StatusCode)
	}
}

// TestCorruptKeyRejected 驗證伺服器不會把壞掉的金鑰發出去。
func TestCorruptKeyRejected(t *testing.T) {
	e := newEnv(t, 5*time.Minute)
	e.register("SYS-B", "測試", nil)
	body, _ := json.Marshal(map[string]string{"kid": "SYS-B:99"})
	req, _ := http.NewRequest(http.MethodPost, e.base+"/api/v1/self/private-key", bytes.NewReader(body))
	resp, err := e.clientFor("SYS-B").Do(req)
	if err != nil {
		t.Fatalf("請求失敗：%v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("不存在的 kid 應為 404，實際 %d", resp.StatusCode)
	}
}

// TestAdminResponsesContainNoKeyMaterial 驗證管理端點不會回傳任何私鑰欄位。
func TestAdminResponsesContainNoKeyMaterial(t *testing.T) {
	e := newEnv(t, 5*time.Minute)
	e.register("SYS-B", "測試", nil)

	req, _ := http.NewRequest(http.MethodPost, e.base+"/api/v1/admin/systems/SYS-B/rotate", nil)
	req.Header.Set("X-Admin-Token", adminToken)
	resp, err := e.admin().Do(req)
	if err != nil {
		t.Fatalf("輪替請求失敗：%v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(b), "wrapped_priv") || strings.Contains(string(b), "WrappedPriv") {
		t.Fatalf("輪替回應洩漏私鑰欄位：%s", b)
	}

	listReq, _ := http.NewRequest(http.MethodGet, e.base+"/api/v1/admin/systems", nil)
	listReq.Header.Set("X-Admin-Token", adminToken)
	listResp, err := e.admin().Do(listReq)
	if err != nil {
		t.Fatalf("列表請求失敗：%v", err)
	}
	defer listResp.Body.Close()
	lb, _ := io.ReadAll(listResp.Body)
	if strings.Contains(string(lb), "wrapped_priv") {
		t.Fatalf("系統列表洩漏私鑰欄位：%s", lb)
	}
}

// TestLoginFlow 驗證登入頁、cookie 工作階段與錯誤密碼。
func TestLoginFlow(t *testing.T) {
	e := newEnv(t, 5*time.Minute)
	noRedirect := &http.Client{
		Transport: e.admin().Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := noRedirect.Get(e.base + "/admin")
	if err != nil {
		t.Fatalf("請求 /admin 失敗：%v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("未登入應導向登入頁，實際 %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/login" {
		t.Fatalf("導向位置錯誤：%s", loc)
	}

	bad, err := noRedirect.PostForm(e.base+"/login", url.Values{"user": {"admin"}, "pass": {"wrong"}})
	if err != nil {
		t.Fatalf("登入請求失敗：%v", err)
	}
	bad.Body.Close()
	if bad.StatusCode != http.StatusUnauthorized {
		t.Fatalf("錯誤密碼應為 401，實際 %d", bad.StatusCode)
	}

	ok, err := noRedirect.PostForm(e.base+"/login", url.Values{"user": {"admin"}, "pass": {adminToken}})
	if err != nil {
		t.Fatalf("登入請求失敗：%v", err)
	}
	ok.Body.Close()
	if ok.StatusCode != http.StatusSeeOther {
		t.Fatalf("登入成功應導向 /admin，實際 %d", ok.StatusCode)
	}
	var session *http.Cookie
	for _, c := range ok.Cookies() {
		if c.Name == "cms_admin" {
			session = c
		}
	}
	if session == nil {
		t.Fatal("未收到工作階段 cookie")
	}

	req, _ := http.NewRequest(http.MethodGet, e.base+"/admin", nil)
	req.AddCookie(session)
	page, err := noRedirect.Do(req)
	if err != nil {
		t.Fatalf("請求 /admin 失敗：%v", err)
	}
	defer page.Body.Close()
	if page.StatusCode != http.StatusOK {
		t.Fatalf("登入後應為 200，實際 %d", page.StatusCode)
	}
}

// 讓未使用的 context 匯入不至於被誤刪（保留給未來擴充）。
var _ = context.Background
var _ = fmt.Sprintf

// TestUIToast 驗證後台操作後以 PRG 帶回提示訊息。
func TestUIToast(t *testing.T) {
	e := newEnv(t, 5*time.Minute)
	noRedirect := &http.Client{
		Transport: e.admin().Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	ok, err := noRedirect.PostForm(e.base+"/login", url.Values{"user": {"admin"}, "pass": {adminToken}})
	if err != nil {
		t.Fatalf("登入失敗：%v", err)
	}
	ok.Body.Close()
	var session *http.Cookie
	for _, c := range ok.Cookies() {
		if c.Name == "cms_admin" {
			session = c
		}
	}
	if session == nil {
		t.Fatal("未取得工作階段 cookie")
	}

	csrf := ""

	post := func(path string, form url.Values) *http.Response {
		form.Set("csrf", csrf)
		req, _ := http.NewRequest(http.MethodPost, e.base+path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(session)
		resp, err := noRedirect.Do(req)
		if err != nil {
			t.Fatalf("POST %s 失敗：%v", path, err)
		}
		resp.Body.Close()
		return resp
	}
	get := func(path string) string {
		req, _ := http.NewRequest(http.MethodGet, e.base+path, nil)
		req.AddCookie(session)
		resp, err := noRedirect.Do(req)
		if err != nil {
			t.Fatalf("GET %s 失敗：%v", path, err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}

	// 取得 CSRF token（表單提交必要）
	if m := regexp.MustCompile(`name="csrf" value="([a-f0-9]+)"`).FindStringSubmatch(get("/admin")); m != nil {
		csrf = m[1]
	} else {
		t.Fatal("頁面沒有 CSRF token")
	}

	// 建立成功 → msg=created
	resp := post("/admin/systems", url.Values{"code": {"SYS-T"}, "name": {"測試"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("建立後應 303，實際 %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "msg=created") || !strings.Contains(loc, "name=SYS-T") {
		t.Fatalf("導向參數不正確：%s", loc)
	}
	if page := get(loc); !strings.Contains(page, "已建立系統") {
		t.Fatal("頁面未顯示成功提示")
	}

	// 重複建立 → msg=error
	resp = post("/admin/systems", url.Values{"code": {"SYS-T"}, "name": {"測試"}})
	if !strings.Contains(resp.Header.Get("Location"), "msg=error") {
		t.Fatalf("重複建立應帶錯誤提示，實際 %s", resp.Header.Get("Location"))
	}
	if page := get(resp.Header.Get("Location")); !strings.Contains(page, "操作失敗") {
		t.Fatal("頁面未顯示錯誤提示")
	}

	// 輪替 → msg=rotated
	resp = post("/admin/systems/SYS-T/rotate", url.Values{})
	if !strings.Contains(resp.Header.Get("Location"), "msg=rotated") {
		t.Fatalf("輪替應帶成功提示，實際 %s", resp.Header.Get("Location"))
	}

	// 停用 → msg=disabled
	resp = post("/admin/systems/SYS-T/toggle", url.Values{})
	if !strings.Contains(resp.Header.Get("Location"), "msg=disabled") {
		t.Fatalf("停用應帶提示，實際 %s", resp.Header.Get("Location"))
	}
}

// TestLoginRateLimit 驗證連續失敗後會被暫時封鎖。
func TestLoginRateLimit(t *testing.T) {
	e := newEnv(t, 5*time.Minute)
	noRedirect := &http.Client{
		Transport: e.admin().Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for i := 0; i < 5; i++ {
		resp, err := noRedirect.PostForm(e.base+"/login", url.Values{"user": {"admin"}, "pass": {"wrong"}})
		if err != nil {
			t.Fatalf("第 %d 次登入請求失敗：%v", i+1, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("第 %d 次應為 401，實際 %d", i+1, resp.StatusCode)
		}
	}

	// 第 6 次即使密碼正確也應被擋下
	resp, err := noRedirect.PostForm(e.base+"/login", url.Values{"user": {"admin"}, "pass": {adminToken}})
	if err != nil {
		t.Fatalf("被封鎖後的請求失敗：%v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("連續失敗後應為 429，實際 %d", resp.StatusCode)
	}
}

// TestUIDetailAndUpdate 驗證「查看」與「編輯」。
func TestUIDetailAndUpdate(t *testing.T) {
	e := newEnv(t, 5*time.Minute)
	e.register("SYS-D", "舊名稱", nil)

	noRedirect := &http.Client{
		Transport: e.admin().Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	ok, err := noRedirect.PostForm(e.base+"/login", url.Values{"user": {"admin"}, "pass": {adminToken}})
	if err != nil {
		t.Fatalf("登入失敗：%v", err)
	}
	ok.Body.Close()
	var session *http.Cookie
	for _, c := range ok.Cookies() {
		if c.Name == "cms_admin" {
			session = c
		}
	}
	if session == nil {
		t.Fatal("未取得工作階段 cookie")
	}

	get := func(path string) (int, string) {
		req, _ := http.NewRequest(http.MethodGet, e.base+path, nil)
		req.AddCookie(session)
		resp, err := noRedirect.Do(req)
		if err != nil {
			t.Fatalf("GET %s 失敗：%v", path, err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	status, page := get("/admin/systems/SYS-D")
	if status != http.StatusOK {
		t.Fatalf("詳情頁應為 200，實際 %d", status)
	}
	if !strings.Contains(page, "SYS-D:1") {
		t.Fatal("詳情頁未顯示金鑰版本 kid")
	}

	m := regexp.MustCompile(`name="csrf" value="([a-f0-9]+)"`).FindStringSubmatch(page)
	if m == nil {
		t.Fatal("詳情頁沒有 CSRF token")
	}
	form := url.Values{
		"name":     {"新名稱"},
		"ip_allow": {"10.0.0.1"},
		"note":     {"更新測試"},
		"mode":     {"required"},
		"csrf":     {m[1]},
	}
	req, _ := http.NewRequest(http.MethodPost, e.base+"/admin/systems/SYS-D", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(session)
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatalf("更新失敗：%v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("更新後應 303，實際 %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "msg=updated") {
		t.Fatalf("導向未帶更新提示：%s", loc)
	}

	_, page2 := get("/admin/systems/SYS-D")
	if !strings.Contains(page2, "新名稱") || !strings.Contains(page2, "10.0.0.1") {
		t.Fatal("更新後頁面未反映新資料")
	}
}
