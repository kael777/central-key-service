// Command dbsetup 建立資料庫與資料表。
//
//	go run ./cmd/dbsetup -dsn "root:pass@tcp(127.0.0.1:3306)/" -db cms_key
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"

	_ "github.com/go-sql-driver/mysql"

	"example.com/key-sdk/central"
)

func main() {
	dsn := flag.String("dsn", "", "伺服器層級 DSN（不含資料庫），例 root:pass@tcp(127.0.0.1:3306)/")
	dbName := flag.String("db", "cms_key", "資料庫名稱")
	reset := flag.Bool("reset", false, "清空既有資料（開發用，會刪除所有系統與金鑰）")
	flag.Parse()
	if *dsn == "" {
		log.Fatal("需要 -dsn")
	}

	server, err := sql.Open("mysql", *dsn)
	if err != nil {
		log.Fatalf("連線失敗：%v", err)
	}
	defer server.Close()
	if err := server.Ping(); err != nil {
		log.Fatalf("無法連線 MySQL：%v", err)
	}
	if _, err := server.Exec(fmt.Sprintf(
		"CREATE DATABASE IF NOT EXISTS `%s` DEFAULT CHARACTER SET utf8mb4", *dbName)); err != nil {
		log.Fatalf("建立資料庫失敗：%v", err)
	}

	target := *dsn + *dbName + "?parseTime=true&loc=UTC&charset=utf8mb4"
	db, err := sql.Open("mysql", target)
	if err != nil {
		log.Fatalf("連線資料庫失敗：%v", err)
	}
	defer db.Close()
	if err := central.EnsureSchema(db); err != nil {
		log.Fatalf("建立資料表失敗：%v", err)
	}
	if *reset {
		for _, tbl := range []string{"key_versions", "systems", "audit_log", "service_locks"} {
			if _, err := db.Exec("DELETE FROM " + tbl); err != nil {
				log.Fatalf("清空 %s 失敗：%v", tbl, err)
			}
		}
		fmt.Println("已清空既有資料")
	}
	fmt.Printf("完成：資料庫 %s 與資料表已就緒\n", *dbName)
	fmt.Printf("DSN：%s\n", target)
}
