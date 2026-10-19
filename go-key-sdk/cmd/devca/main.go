// Command devca 產生開發／內網測試用的 CA、伺服器憑證與各系統用戶端憑證。
//
//	go run ./cmd/devca -out ./certs -systems SYS-A,SYS-B
//	go run ./cmd/devca -out ./certs -count 50 -prefix SYS-
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"example.com/key-sdk/central"
)

func main() {
	out := flag.String("out", "./certs", "輸出目錄")
	systems := flag.String("systems", "SYS-A,SYS-B", "以逗號分隔的系統代碼")
	count := flag.Int("count", 0, "若大於 0，改為產生 <prefix>1..N 的系統")
	prefix := flag.String("prefix", "SYS-", "搭配 -count 使用的代碼前綴")
	hosts := flag.String("server-host", "127.0.0.1,localhost", "伺服器憑證的 SAN（逗號分隔）")
	ttlDays := flag.Int("ttl-days", 365, "憑證有效天數")
	flag.Parse()

	ttl := time.Duration(*ttlDays) * 24 * time.Hour
	if err := os.MkdirAll(filepath.Join(*out, "clients"), 0o755); err != nil {
		log.Fatalf("建立目錄失敗：%v", err)
	}

	ca, err := central.GenerateCA("CMS", "CMS Development CA")
	if err != nil {
		log.Fatalf("產生 CA 失敗：%v", err)
	}
	caKey, err := marshalKey(ca)
	if err != nil {
		log.Fatalf("編碼 CA 私鑰失敗：%v", err)
	}
	if err := central.WritePair(filepath.Join(*out, "ca.crt"), filepath.Join(*out, "ca.key"), ca.CertPEM, caKey); err != nil {
		log.Fatalf("寫出 CA 失敗：%v", err)
	}

	certPEM, keyPEM, err := ca.IssueServer(strings.Split(*hosts, ","), 2*365*24*time.Hour)
	if err != nil {
		log.Fatalf("簽發伺服器憑證失敗：%v", err)
	}
	if err := central.WritePair(filepath.Join(*out, "server.crt"), filepath.Join(*out, "server.key"), certPEM, keyPEM); err != nil {
		log.Fatalf("寫出伺服器憑證失敗：%v", err)
	}

	var codes []string
	if *count > 0 {
		for i := 1; i <= *count; i++ {
			codes = append(codes, fmt.Sprintf("%s%d", *prefix, i))
		}
	} else {
		for _, c := range strings.Split(*systems, ",") {
			if c = strings.TrimSpace(c); c != "" {
				codes = append(codes, c)
			}
		}
	}

	for _, code := range codes {
		c, k, err := ca.IssueClient(code, ttl)
		if err != nil {
			log.Fatalf("簽發 %s 憑證失敗：%v", code, err)
		}
		if err := central.WritePair(
			filepath.Join(*out, "clients", code+".crt"),
			filepath.Join(*out, "clients", code+".key"), c, k); err != nil {
			log.Fatalf("寫出 %s 憑證失敗：%v", code, err)
		}
	}

	fmt.Printf("完成：%s\n", *out)
	fmt.Printf("  ca.crt / ca.key              CA（ca.key 請妥善保管）\n")
	fmt.Printf("  server.crt / server.key      伺服器憑證（SAN: %s）\n", *hosts)
	fmt.Printf("  clients/<CODE>.crt/.key      %d 個系統憑證\n", len(codes))
	fmt.Printf("\n啟動中央服務：\n  go run ./cmd/central -addr :8443 -cert %s -key %s -ca %s -admin-token dev-token\n",
		filepath.Join(*out, "server.crt"), filepath.Join(*out, "server.key"), filepath.Join(*out, "ca.crt"))
}

func marshalKey(ca *central.CA) ([]byte, error) {
	return central.MarshalKeyPEM(ca)
}
