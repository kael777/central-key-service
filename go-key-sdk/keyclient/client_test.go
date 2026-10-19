package keyclient_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"example.com/key-sdk/keyclient"
	"example.com/key-sdk/keycrypto"
)

// 測試用金鑰對：模擬「自身系統」的目前版本。
func testKey(t *testing.T) (*ecdsa.PrivateKey, string, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("產生金鑰失敗：%v", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("編碼公鑰失敗：%v", err)
	}
	return priv, base64.StdEncoding.EncodeToString(spki), spki
}

func newServer(t *testing.T, kid string, spkiB64 string, priv *ecdsa.PrivateKey, status int) *httptest.Server {
	t.Helper()
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("編碼私鑰失敗：%v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/sync", func(w http.ResponseWriter, r *http.Request) {
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		if r.Header.Get("User-Agent") == "" || len(r.Header.Get("User-Agent")) < len("key-sdk-") {
			t.Errorf("缺少 User-Agent：%q", r.Header.Get("User-Agent"))
		}
		w.Header().Set("ETag", `W/"1"`)
		w.Header().Set("Content-Type", "application/json")
		body := map[string]any{
			"server_time": time.Now().UTC().Format(time.RFC3339),
			"self": map[string]any{
				"system_code":      "SYS-B",
				"encryption":       map[string]any{"mode": "required"},
				"decrypt_versions": []map[string]string{{"kid": kid}},
			},
			"peers": map[string]any{
				"SYS-B": map[string]string{"kid": kid, "alg": "ECIES-P256-AES256GCM", "public_key": spkiB64},
			},
			"etag": `W/"1"`,
		}
		_ = json.NewEncoder(w).Encode(body)
	})
	mux.HandleFunc("/api/v1/self/private-key", func(w http.ResponseWriter, r *http.Request) {
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"kid":             kid,
			"private_key_b64": base64.StdEncoding.EncodeToString(pkcs8),
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	priv, spkiB64, _ := testKey(t)
	srv := newServer(t, "SYS-B:3", spkiB64, priv, http.StatusOK)

	c, err := keyclient.New(keyclient.Config{
		BaseURL:    srv.URL,
		SystemCode: "SYS-B",
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("建立 client 失敗：%v", err)
	}

	token, err := c.Encrypt(context.Background(), "SYS-B", "urlparam", []byte("a=1&b=2"))
	if err != nil {
		t.Fatalf("加密失敗：%v", err)
	}
	got, err := c.Decrypt(context.Background(), token, "urlparam")
	if err != nil {
		t.Fatalf("解密失敗：%v", err)
	}
	if string(got) != "a=1&b=2" {
		t.Fatalf("明文不符：%q", got)
	}

	// 不同的 purpose 必須失敗（AAD 綁定）
	if _, err := c.Decrypt(context.Background(), token, "body"); keycrypto.CodeOf(err) != keycrypto.ErrAuth {
		t.Fatalf("purpose 不符應回 ERR_AUTH，實際 %v", err)
	}

	// 快照應被快取，第二次加密不再打伺服器
	if c.Snapshot() == nil {
		t.Fatal("快照為 nil")
	}
}

func TestUnauthorized(t *testing.T) {
	priv, spkiB64, _ := testKey(t)
	srv := newServer(t, "SYS-B:3", spkiB64, priv, http.StatusForbidden)
	c, _ := keyclient.New(keyclient.Config{BaseURL: srv.URL, SystemCode: "SYS-B", HTTPClient: srv.Client()})

	if _, err := c.Encrypt(context.Background(), "SYS-B", "urlparam", []byte("x")); keycrypto.CodeOf(err) != keycrypto.ErrUnauthorized {
		t.Fatalf("預期 ERR_UNAUTHORIZED，實際 %v", err)
	}
}

func TestUnknownPeer(t *testing.T) {
	priv, spkiB64, _ := testKey(t)
	srv := newServer(t, "SYS-B:3", spkiB64, priv, http.StatusOK)
	c, _ := keyclient.New(keyclient.Config{BaseURL: srv.URL, SystemCode: "SYS-B", HTTPClient: srv.Client()})

	if _, err := c.Encrypt(context.Background(), "SYS-Q", "urlparam", []byte("x")); keycrypto.CodeOf(err) != keycrypto.ErrUnknownKID {
		t.Fatalf("預期 ERR_UNKNOWN_KID，實際 %v", err)
	}
}

// TestStaleAfterTimeout 驗證：中央不可用超過上限時，加密端必須回 ERR_STALE，
// 且不得退化為明文。
func TestStaleAfterTimeout(t *testing.T) {
	old := keyclient.MaxStaleness
	keyclient.MaxStaleness = 20 * time.Millisecond
	t.Cleanup(func() { keyclient.MaxStaleness = old })

	priv, spkiB64, _ := testKey(t)
	srv := newServer(t, "SYS-B:3", spkiB64, priv, http.StatusOK)
	c, _ := keyclient.New(keyclient.Config{BaseURL: srv.URL, SystemCode: "SYS-B", HTTPClient: srv.Client()})

	if _, err := c.Encrypt(context.Background(), "SYS-B", "urlparam", []byte("x")); err != nil {
		t.Fatalf("第一次加密失敗：%v", err)
	}
	srv.Close()
	time.Sleep(40 * time.Millisecond)

	if _, err := c.Encrypt(context.Background(), "SYS-B", "urlparam", []byte("x")); keycrypto.CodeOf(err) != keycrypto.ErrStale {
		t.Fatalf("預期 ERR_STALE，實際 %v", err)
	}
}
