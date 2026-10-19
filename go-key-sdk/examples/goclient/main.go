// Command goclient 示範業務系統如何用 Go SDK。
//
// 加密（SYS-A 發給 SYS-B）：
//
//	go run ./examples/goclient -system SYS-A -peer SYS-B -data "a=1&b=2"
//
// 解密（SYS-B 解開上面產生的 token）：
//
//	go run ./examples/goclient -system SYS-B -token "KEY1.SYS-B:1...."
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"example.com/key-sdk/keyclient"
)

func main() {
	base := flag.String("base", "https://127.0.0.1:8443", "中央服務位址")
	system := flag.String("system", "SYS-A", "本系統代碼")
	peer := flag.String("peer", "SYS-B", "對端系統代碼（加密時使用）")
	certs := flag.String("certs", "certs", "憑證目錄（內含 clients/<code>.crt/.key）")
	caFile := flag.String("ca", "", "CA 路徑；留空時若 <certs>/ca.crt 存在則使用，否則用系統信任庫（公網公開 CA）")
	purpose := flag.String("purpose", "urlparam", "用途標記，解密時必須一致")
	data := flag.String("data", "a=1&b=2", "要加密的明文")
	token := flag.String("token", "", "要解密的 token（留空則執行加密）")
	flag.Parse()

	caPath := *caFile
	if caPath == "" {
		candidate := *certs + "/ca.crt"
		if _, err := os.Stat(candidate); err == nil {
			caPath = candidate
		}
	}
	if strings.EqualFold(caPath, "none") {
		caPath = ""
	}

	c, err := keyclient.New(keyclient.Config{
		BaseURL:    *base,
		SystemCode: *system,
		ClientCert: fmt.Sprintf("%s/clients/%s.crt", *certs, *system),
		ClientKey:  fmt.Sprintf("%s/clients/%s.key", *certs, *system),
		CAFile:     caPath,
	})
	if err != nil {
		log.Fatalf("建立 client 失敗：%v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if *token == "" {
		t, err := c.Encrypt(ctx, *peer, *purpose, []byte(*data))
		if err != nil {
			log.Fatalf("加密失敗：%v", err)
		}
		fmt.Println(t)
		return
	}

	pt, err := c.Decrypt(ctx, *token, *purpose)
	if err != nil {
		log.Fatalf("解密失敗：%v", err)
	}
	fmt.Println(string(pt))
}
