package central_test

import (
	"os"
	"path/filepath"
	"testing"

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
