// sqlkill：中斷指定資料庫的連線，用來演練 MySQL 斷線與復原。
// 用法：go run ./cmd/sqlkill -dsn "root:pass@tcp(127.0.0.1:3306)/" -db cms_key
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"os"

	_ "github.com/go-sql-driver/mysql"
)

func main() {
	dsn := flag.String("dsn", "", "MySQL DSN（不帶 db）")
	db := flag.String("db", "cms_key", "要中斷連線的資料庫")
	flag.Parse()
	if *dsn == "" {
		fmt.Fprintln(os.Stderr, "需要 -dsn")
		os.Exit(2)
	}

	admin, err := sql.Open("mysql", *dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "連線失敗：%v\n", err)
		os.Exit(1)
	}
	defer admin.Close()

	rows, err := admin.Query("SELECT id FROM information_schema.processlist WHERE db = ? AND id <> CONNECTION_ID()", *db)
	if err != nil {
		fmt.Fprintf(os.Stderr, "查詢連線失敗：%v\n", err)
		os.Exit(1)
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()

	for _, id := range ids {
		if _, err := admin.Exec(fmt.Sprintf("KILL %d", id)); err != nil {
			fmt.Printf("kill %d: %v\n", id, err)
		}
	}
	fmt.Printf("已中斷 %d 條連線（db=%s）\n", len(ids), *db)
}
