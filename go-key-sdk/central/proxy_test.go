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
