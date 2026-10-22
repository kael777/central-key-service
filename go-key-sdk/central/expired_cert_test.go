package central

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// 過期憑證必須在 TLS 握手就被拒絕。
func TestExpiredClientCertRejected(t *testing.T) {
	ca, err := GenerateCA("CMS", "CMS Test CA")
	if err != nil {
		t.Fatalf("產生 CA 失敗：%v", err)
	}
	pool, err := ca.Pool()
	if err != nil {
		t.Fatalf("載入 CA 失敗：%v", err)
	}

	expiredCert, expiredKey, err := ca.IssueClient("SYS-A", -time.Hour)
	if err != nil {
		t.Fatalf("簽發過期憑證失敗：%v", err)
	}
	clientPair, err := tls.X509KeyPair(expiredCert, expiredKey)
	if err != nil {
		t.Fatalf("載入憑證失敗：%v", err)
	}

	serverCert, serverKey, err := ca.IssueServer([]string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatalf("簽發伺服器憑證失敗：%v", err)
	}
	serverPair, err := tls.X509KeyPair(serverCert, serverKey)
	if err != nil {
		t.Fatalf("載入伺服器憑證失敗：%v", err)
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverPair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	defer srv.Close()

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		Certificates: []tls.Certificate{clientPair},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
	}}}
	resp, err := client.Get(srv.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatalf("過期憑證不應完成請求，實際狀態 %d", resp.StatusCode)
	}
	t.Logf("如預期被拒：%v", err)
}
