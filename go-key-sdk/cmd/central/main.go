// Command central 啟動中央 KEY 管理服務。
//
// 最簡：go run ./cmd/central -config config.example.json
//
// 設定優先序：命令列旗標 > 環境變數（僅 KEY_KEK）> 設定檔 > 內建預設值。
package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"example.com/key-sdk/central"
)

func main() {
	cfgPath := flag.String("config", "", "JSON 設定檔路徑（可省略，全部用旗標）")

	addr := flag.String("addr", ":8443", "監聽位址")
	cert := flag.String("cert", "certs/server.crt", "伺服器憑證")
	key := flag.String("key", "certs/server.key", "伺服器私鑰")
	caPath := flag.String("ca", "certs/ca.crt", "CA 憑證（用於驗證用戶端）")
	adminToken := flag.String("admin-token", "dev-token", "管理權杖（API 與後台頁面）")
	adminUser := flag.String("admin-user", "admin", "後台頁面帳號")
	kekHex := flag.String("kek", "", "KEK 十六進位（32 bytes）")
	dataFile := flag.String("data", "", "狀態檔（留空為純記憶體）")
	dsn := flag.String("dsn", "", "MySQL DSN，例如 user:pass@tcp(127.0.0.1:3306)/cms_key?parseTime=true")
	auditFile := flag.String("audit", "", "稽核 JSONL 檔（留空只保留記憶體）")
	grace := flag.Duration("grace", 5*time.Minute, "新舊版本解密緩衝期")
	prepublish := flag.Duration("prepublish", 10*time.Minute, "新公鑰提前發布時間")
	rotation := flag.Duration("rotation", 30*24*time.Hour, "自動輪替週期")
	flag.Parse()

	// 記錄哪些旗標被明確指定，用於覆寫設定檔。
	set := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { set[f.Name] = true })

	if *cfgPath != "" {
		fc, err := central.LoadFileConfig(*cfgPath)
		if err != nil {
			log.Fatalf("%v", err)
		}
		if fc.Addr != "" && !set["addr"] {
			*addr = fc.Addr
		}
		if fc.Cert != "" && !set["cert"] {
			*cert = fc.Cert
		}
		if fc.Key != "" && !set["key"] {
			*key = fc.Key
		}
		if fc.CA != "" && !set["ca"] {
			*caPath = fc.CA
		}
		if fc.AdminToken != "" && !set["admin-token"] {
			*adminToken = fc.AdminToken
		}
		if fc.AdminUser != "" && !set["admin-user"] {
			*adminUser = fc.AdminUser
		}
		if fc.KEK != "" && !set["kek"] {
			*kekHex = fc.KEK
		}
		if fc.DSN != "" && !set["dsn"] {
			*dsn = fc.DSN
		}
		if fc.Data != "" && !set["data"] {
			*dataFile = fc.Data
		}
		if fc.Audit != "" && !set["audit"] {
			*auditFile = fc.Audit
		}
		if fc.Grace != "" && !set["grace"] {
			d, err := time.ParseDuration(fc.Grace)
			if err != nil {
				log.Fatalf("設定檔 grace 格式錯誤：%v", err)
			}
			*grace = d
		}
		if fc.Prepublish != "" && !set["prepublish"] {
			d, err := time.ParseDuration(fc.Prepublish)
			if err != nil {
				log.Fatalf("設定檔 prepublish 格式錯誤：%v", err)
			}
			*prepublish = d
		}
		if fc.Rotation != "" && !set["rotation"] {
			d, err := time.ParseDuration(fc.Rotation)
			if err != nil {
				log.Fatalf("設定檔 rotation 格式錯誤：%v", err)
			}
			*rotation = d
		}
	}

	// KEK：旗標 > 環境變數 > 設定檔（已寫入 kekHex）
	var kek []byte
	var err error
	if *kekHex == "" {
		*kekHex = os.Getenv("KEY_KEK")
	}
	if *kekHex != "" {
		kek, err = central.HexKey(*kekHex)
		if err != nil {
			log.Fatalf("KEK 無效：%v", err)
		}
	} else {
		log.Println("警告：未提供 KEK，使用開發用預設金鑰；正式環境必須設定 KEY_KEK")
	}

	caPEM, err := os.ReadFile(*caPath)
	if err != nil {
		log.Fatalf("讀取 CA 失敗：%v", err)
	}
	tlsCfg, err := central.NewTLSConfig(caPEM)
	if err != nil {
		log.Fatalf("建立 TLS 設定失敗：%v", err)
	}
	pair, err := tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		log.Fatalf("載入伺服器憑證失敗：%v", err)
	}
	tlsCfg.Certificates = []tls.Certificate{pair}

	svc := central.NewService(central.Config{
		Grace:      *grace,
		Prepublish: *prepublish,
		Rotation:   *rotation,
		KEK:        kek,
		AdminToken: *adminToken,
		AdminUser:  *adminUser,
		DataFile:   *dataFile,
		DSN:        *dsn,
		AuditFile:  *auditFile,
	})
	srv := central.NewServer(svc)

	go func() {
		tick := time.NewTicker(time.Second)
		rotate := time.NewTicker(time.Minute)
		defer tick.Stop()
		defer rotate.Stop()
		for {
			select {
			case now := <-tick.C:
				svc.Tick(now)
			case now := <-rotate.C:
				if n, err := svc.AutoRotate(now); err != nil {
					log.Printf("自動輪替失敗：%v", err)
				} else if n > 0 {
					log.Printf("自動輪替 %d 個系統", n)
				}
			}
		}
	}()

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
	}
	log.Printf("中央 KEY 服務：https://%s（grace=%s, rotation=%s）", *addr, *grace, *rotation)
	log.Printf("後台登入頁：https://%s/login（帳號 %s，密碼 = 管理權杖）", *addr, *adminUser)
	if err := httpSrv.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("服務結束：%v", err)
	}
}
