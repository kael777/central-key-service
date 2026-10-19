package central_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"example.com/key-sdk/central"
)

func TestLoadFileConfig(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	content := `{
	  "addr": "127.0.0.1:9443",
	  "admin_token": "tok",
	  "admin_user": "ops",
	  "grace": "5m",
	  "rotation": "720h",
	  "data": "data/state.json"
	}`
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	fc, err := central.LoadFileConfig(p)
	if err != nil {
		t.Fatalf("載入失敗：%v", err)
	}
	if fc.Addr != "127.0.0.1:9443" || fc.AdminToken != "tok" || fc.AdminUser != "ops" {
		t.Fatalf("欄位不符：%+v", fc)
	}
	if fc.Grace != "5m" || fc.Rotation != "720h" {
		t.Fatalf("時間欄位不符：%+v", fc)
	}
}

func TestLoadFileConfigInvalid(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(p, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := central.LoadFileConfig(p); err == nil {
		t.Fatal("壞掉的設定檔應回傳錯誤")
	}
	if _, err := central.LoadFileConfig(filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("不存在的設定檔應回傳錯誤")
	}
}

// TestFileStorePersistence 驗證檔案後端重啟後仍載入既有系統（回歸測試）。
func TestFileStorePersistence(t *testing.T) {
	dir := t.TempDir()
	dataFile := filepath.Join(dir, "state.json")
	cfg := central.Config{
		DataFile: dataFile,
		KEK:      make([]byte, 32),
		Grace:    time.Minute,
	}

	a := central.NewService(cfg)
	if _, err := a.Register("SYS-A", "A", nil, "", "test", ""); err != nil {
		t.Fatalf("登記失敗：%v", err)
	}
	if _, err := a.Register("SYS-B", "B", nil, "", "test", ""); err != nil {
		t.Fatalf("登記失敗：%v", err)
	}
	_ = a.Close()

	b := central.NewService(cfg)
	defer b.Close()
	if got := len(b.Systems()); got != 2 {
		t.Fatalf("重啟後應載入 2 個系統，實際 %d", got)
	}
	for _, code := range []string{"SYS-A", "SYS-B"} {
		if _, err := b.Sync(code); err != nil {
			t.Fatalf("重啟後 %s 同步失敗：%v", code, err)
		}
	}
}
