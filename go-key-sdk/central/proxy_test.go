package central_test

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"example.com/key-sdk/central"
)

// TestProxyHeaderIdentity 驗證：Nginx 終結 mTLS 後，後端可依受信代理標頭識別系統。
func TestProxyHeaderIdentity(t *testing.T) {
	ca, err := central.GenerateCA("CMS", "CMS Test CA")
	if err != nil {
		t.Fatalf("CA 失敗：%v", err)
	}
	pool, _ := ca.Pool()
	serverCert, serverKey, err := ca.IssueServer([]string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatalf("伺服器憑證失敗：%v", err)
	}
	pair, err := tls.X509KeyPair(serverCert, serverKey)
	if err != nil {
		t.Fatalf("載入憑證失敗：%v", err)
	}

	svc := central.NewService(central.Config{
		KEK:            make([]byte, 32),
		AdminToken:     "tok",
		Grace:          time.Minute,
		TrustedProxies: []string{"127.0.0.1/32"},
		ProxySecret:    "proxy-secret",
	})
	if _, err := svc.Register("SYS-A", "A", nil, "", "test", ""); err != nil {
		t.Fatalf("登記失敗：%v", err)
	}

	s := central.NewServer(svc)
	srv := httptest.NewUnstartedServer(s.Handler())
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}

	do := func(headers map[string]string) int {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/sync", nil)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("請求失敗：%v", err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	okHeaders := map[string]string{
		"X-Proxy-Secret":  "proxy-secret",
		"X-Client-Verify": "SUCCESS",
		"X-Client-CN":     "SYS-A",
	}
	if got := do(okHeaders); got != http.StatusOK {
		t.Fatalf("受信代理轉發應成功，實際 %d", got)
	}

	// 舊版 nginx 沒有 $ssl_client_s_dn_cn，改送完整 DN
	dnHeaders := map[string]string{
		"X-Proxy-Secret":  "proxy-secret",
		"X-Client-Verify": "SUCCESS",
		"X-Client-CN":     "/C=CN/O=CMS/CN=SYS-A",
	}
	if got := do(dnHeaders); got != http.StatusOK {
		t.Fatalf("完整 DN 應可解析出 CN，實際 %d", got)
	}

	// 密鑰錯誤
	bad := map[string]string{
		"X-Proxy-Secret":  "wrong",
		"X-Client-Verify": "SUCCESS",
		"X-Client-CN":     "SYS-A",
	}
	if got := do(bad); got != http.StatusUnauthorized {
		t.Fatalf("錯誤密鑰應為 401，實際 %d", got)
	}

	// 缺少憑證驗證結果
	noVerify := map[string]string{
		"X-Proxy-Secret": "proxy-secret",
		"X-Client-CN":    "SYS-A",
	}
	if got := do(noVerify); got != http.StatusUnauthorized {
		t.Fatalf("缺少 X-Client-Verify 應為 401，實際 %d", got)
	}

	// 完全沒有標頭（直連）
	if got := do(map[string]string{}); got != http.StatusUnauthorized {
		t.Fatalf("直連無憑證應為 401，實際 %d", got)
	}
}

// TestAdminCIDRBlocksLogin 驗證後台網段限制也涵蓋登入端點。
func TestAdminCIDRBlocksLogin(t *testing.T) {
	ca, err := central.GenerateCA("CMS", "CMS Test CA")
	if err != nil {
		t.Fatalf("CA 失敗：%v", err)
	}
	pool, _ := ca.Pool()
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
		AdminToken: "tok",
		Grace:      time.Minute,
		AdminCIDR:  []string{"10.20.0.0/16"}, // 不含 127.0.0.1
	})
	s := central.NewServer(svc)
	srv := httptest.NewUnstartedServer(s.Handler())
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	for _, path := range []string{"/login", "/admin"} {
		resp, err := client.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("請求 %s 失敗：%v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("%s 應被網段限制擋下（403），實際 %d", path, resp.StatusCode)
		}
	}
}

// TestProxyClientIPAllowlist 驗證代理模式下 ip_allow 使用 X-Forwarded-For。
func TestProxyClientIPAllowlist(t *testing.T) {
	ca, err := central.GenerateCA("CMS", "CMS Test CA")
	if err != nil {
		t.Fatalf("CA 失敗：%v", err)
	}
	pool, _ := ca.Pool()
	serverCert, serverKey, err := ca.IssueServer([]string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatalf("伺服器憑證失敗：%v", err)
	}
	pair, err := tls.X509KeyPair(serverCert, serverKey)
	if err != nil {
		t.Fatalf("載入憑證失敗：%v", err)
	}

	svc := central.NewService(central.Config{
		KEK:            make([]byte, 32),
		AdminToken:     "tok",
		Grace:          time.Minute,
		TrustedProxies: []string{"127.0.0.1/32"},
		ProxySecret:    "s",
	})
	if _, err := svc.Register("SYS-A", "A", []string{"10.1.1.11"}, "", "test", ""); err != nil {
		t.Fatalf("登記失敗：%v", err)
	}

	s := central.NewServer(svc)
	srv := httptest.NewUnstartedServer(s.Handler())
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	do := func(xff string) int {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/sync", nil)
		req.Header.Set("X-Proxy-Secret", "s")
		req.Header.Set("X-Client-Verify", "SUCCESS")
		req.Header.Set("X-Client-CN", "SYS-A")
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("請求失敗：%v", err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	if got := do("10.1.1.11"); got != http.StatusOK {
		t.Fatalf("XFF 符合白名單應 200，實際 %d", got)
	}
	if got := do("10.9.9.9"); got != http.StatusForbidden {
		t.Fatalf("XFF 不在白名單應 403，實際 %d", got)
	}
	if got := do(""); got != http.StatusForbidden {
		t.Fatalf("沒有 XFF 應視為 127.0.0.1 並被拒，實際 %d", got)
	}
}
