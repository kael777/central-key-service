// Command smoke 對執行中的中央服務做端到端驗證：
// 登記兩個系統 → A 取得 B 公鑰加密 → B 取得自身私鑰解密 → 比對明文。
//
//	go run ./cmd/smoke -base https://127.0.0.1:18443 -ca certs/ca.crt \
//	  -a-cert certs/clients/SYS-A.crt -a-key certs/clients/SYS-A.key \
//	  -b-cert certs/clients/SYS-B.crt -b-key certs/clients/SYS-B.key
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"example.com/key-sdk/keyclient"
)

func main() {
	base := flag.String("base", "https://127.0.0.1:8443", "中央服務位址")
	caFile := flag.String("ca", "certs/ca.crt", "CA 憑證")
	adminToken := flag.String("admin-token", "dev-token", "管理權杖")
	aCert := flag.String("a-cert", "certs/clients/SYS-A.crt", "A 的用戶端憑證")
	aKey := flag.String("a-key", "certs/clients/SYS-A.key", "A 的私鑰")
	bCert := flag.String("b-cert", "certs/clients/SYS-B.crt", "B 的用戶端憑證")
	bKey := flag.String("b-key", "certs/clients/SYS-B.key", "B 的私鑰")
	flag.Parse()

	caPEM, err := os.ReadFile(*caFile)
	if err != nil {
		log.Fatalf("讀取 CA 失敗：%v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		log.Fatal("CA 憑證無效")
	}
	admin := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}

	for _, s := range []struct{ code, name string }{{"SYS-A", "Sender"}, {"SYS-B", "Receiver"}} {
		body, _ := json.Marshal(map[string]any{"code": s.code, "name": s.name})
		req, _ := http.NewRequest(http.MethodPost, *base+"/api/v1/admin/systems", bytes.NewReader(body))
		req.Header.Set("X-Admin-Token", *adminToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := admin.Do(req)
		if err != nil {
			log.Fatalf("登記 %s 失敗：%v", s.code, err)
		}
		resp.Body.Close()
		fmt.Printf("register %-6s → %d\n", s.code, resp.StatusCode)
	}

	a, err := keyclient.New(keyclient.Config{
		BaseURL: *base, SystemCode: "SYS-A",
		ClientCert: *aCert, ClientKey: *aKey, CAFile: *caFile,
	})
	if err != nil {
		log.Fatalf("建立 A client 失敗：%v", err)
	}
	b, err := keyclient.New(keyclient.Config{
		BaseURL: *base, SystemCode: "SYS-B",
		ClientCert: *bCert, ClientKey: *bKey, CAFile: *caFile,
	})
	if err != nil {
		log.Fatalf("建立 B client 失敗：%v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	payload := []byte("訂單編號=A123456&金額=1000")
	token, err := a.Encrypt(ctx, "SYS-B", "urlparam", payload)
	if err != nil {
		log.Fatalf("A 加密失敗：%v", err)
	}
	fmt.Printf("A encrypt → %s...（%d 字元）\n", token[:24], len(token))

	got, err := b.Decrypt(ctx, token, "urlparam")
	if err != nil {
		log.Fatalf("B 解密失敗：%v", err)
	}
	if !bytes.Equal(got, payload) {
		log.Fatalf("明文不符：%q", got)
	}
	fmt.Printf("B decrypt → %q\n", got)

	if b.Snapshot() == nil {
		if err := b.Refresh(ctx); err != nil {
			log.Fatalf("B 同步失敗：%v", err)
		}
	}
	snapA, snapB := a.Snapshot(), b.Snapshot()
	if snapA == nil || snapB == nil {
		log.Fatal("快照為空")
	}
	fmt.Printf("snapshot A: mode=%s peers=%d\n", snapA.Mode, len(snapA.Peers))
	fmt.Printf("snapshot B: mode=%s decrypt_versions=%d\n", snapB.Mode, len(snapB.DecryptKIDs))
	fmt.Println("PASS  端到端加密／解密成功")
}
