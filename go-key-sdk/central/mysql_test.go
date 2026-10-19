package central

import (
	"bytes"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// 需要真實 MySQL：設定 TEST_MYSQL_DSN 後執行
//
//	TEST_MYSQL_DSN="root:pass@tcp(127.0.0.1:3306)/cms_key?parseTime=true&loc=UTC" go test ./central -run MySQL -v
func mysqlDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("未設定 TEST_MYSQL_DSN，略過 MySQL 整合測試")
	}
	return dsn
}

func cleanMySQL(t *testing.T, dsn string) {
	t.Helper()
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("連線失敗：%v", err)
	}
	defer db.Close()
	for _, tbl := range []string{"key_versions", "systems", "audit_log", "service_locks"} {
		if _, err := db.Exec("DELETE FROM " + tbl); err != nil {
			t.Fatalf("清理 %s 失敗：%v", tbl, err)
		}
	}
}

func TestMySQLSharedState(t *testing.T) {
	dsn := mysqlDSN(t)
	cleanMySQL(t, dsn)

	cfg := Config{DSN: dsn, KEK: bytes.Repeat([]byte{7}, 32), Grace: time.Minute, Rotation: time.Hour}

	a := NewService(cfg)
	defer a.Close()
	if _, err := a.Register("SYS-A", "發送", nil, "", "test", "127.0.0.1"); err != nil {
		t.Fatalf("登記 SYS-A 失敗：%v", err)
	}
	if _, err := a.Register("SYS-B", "接收", nil, "", "test", "127.0.0.1"); err != nil {
		t.Fatalf("登記 SYS-B 失敗：%v", err)
	}

	// 第二個實例：應從 MySQL 載入相同狀態
	b := NewService(cfg)
	defer b.Close()
	if got := len(b.Systems()); got != 2 {
		t.Fatalf("第二實例應載入 2 個系統，實際 %d", got)
	}

	// 在 A 輪替，B 應立即看到新版本（寫入後重新載入）
	if _, err := a.Rotate("SYS-B", "test", "127.0.0.1"); err != nil {
		t.Fatalf("輪替失敗：%v", err)
	}
	snap, err := b.Sync("SYS-B")
	if err != nil {
		t.Fatalf("B 同步失敗：%v", err)
	}
	if len(snap.DecryptVersions) != 2 {
		t.Fatalf("緩衝期內應有 2 個解密版本，實際 %d", len(snap.DecryptVersions))
	}

	// 私鑰可取（KEK 一致）
	if _, err := b.PrivateKey("SYS-B", snap.DecryptVersions[0].KID); err != nil {
		t.Fatalf("取得私鑰失敗：%v", err)
	}

	// 稽核已落庫
	var n int
	db, _ := sql.Open("mysql", dsn)
	defer db.Close()
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&n); err != nil {
		t.Fatalf("查詢稽核失敗：%v", err)
	}
	if n == 0 {
		t.Fatal("稽核紀錄未寫入資料庫")
	}
}

func TestMySQLAutoRotate(t *testing.T) {
	dsn := mysqlDSN(t)
	cleanMySQL(t, dsn)

	const rotation = time.Hour
	cfg := Config{DSN: dsn, KEK: bytes.Repeat([]byte{9}, 32), Grace: time.Minute, Rotation: rotation}
	s := NewService(cfg)
	defer s.Close()
	if _, err := s.Register("SYS-C", "定時輪替", nil, "", "test", ""); err != nil {
		t.Fatalf("登記失敗：%v", err)
	}

	// 以注入的時間推進到輪替週期之後
	due := time.Now().Add(rotation + time.Second)
	n, err := s.AutoRotate(due)
	if err != nil {
		t.Fatalf("自動輪替失敗：%v", err)
	}
	if n != 1 {
		t.Fatalf("應輪替 1 個系統，實際 %d", n)
	}
	// 同一時刻再次呼叫，剛產生的版本尚未到期，不應再輪替
	n2, err := s.AutoRotate(due)
	if err != nil {
		t.Fatalf("第二次自動輪替失敗：%v", err)
	}
	if n2 != 0 {
		t.Fatalf("不應重複輪替，實際 %d", n2)
	}
	if got := len(s.VersionsOf("SYS-C")); got != 2 {
		t.Fatalf("應有 2 個版本，實際 %d", got)
	}
}

func TestMySQLLease(t *testing.T) {
	dsn := mysqlDSN(t)
	cleanMySQL(t, dsn)

	st := newStore(Config{DSN: dsn})
	defer st.Close()

	ok, err := st.TryLease("rotation", "node-a", 300*time.Millisecond)
	if err != nil || !ok {
		t.Fatalf("第一個實例應取得租約：ok=%v err=%v", ok, err)
	}
	ok, err = st.TryLease("rotation", "node-b", 300*time.Millisecond)
	if err != nil {
		t.Fatalf("第二個實例查詢租約失敗：%v", err)
	}
	if ok {
		t.Fatal("租約未過期時不應被第二個實例取得")
	}
	time.Sleep(400 * time.Millisecond)
	ok, err = st.TryLease("rotation", "node-b", 300*time.Millisecond)
	if err != nil || !ok {
		t.Fatalf("租約過期後應可取得：ok=%v err=%v", ok, err)
	}
}
