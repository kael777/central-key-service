package central

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestDeleteSystemRequiresDisabled(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	svc := NewService(policyConfig(&now))
	if _, err := svc.Register("SYS-D", "D", []string{"127.0.0.1"}, "", "test", ""); err != nil {
		t.Fatalf("登記失敗：%v", err)
	}

	// 啟用中不可刪除
	if err := svc.DeleteSystem("SYS-D", "test", ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("啟用中刪除應回 ErrConflict，實際 %v", err)
	}

	if err := svc.SetStatus("SYS-D", false, "test", ""); err != nil {
		t.Fatalf("停用失敗：%v", err)
	}
	if err := svc.DeleteSystem("SYS-D", "test", ""); err != nil {
		t.Fatalf("停用後刪除失敗：%v", err)
	}
	for _, s := range svc.Systems() {
		if s.Code == "SYS-D" {
			t.Fatal("系統仍存在")
		}
	}
	if len(svc.Versions("SYS-D")) != 0 {
		t.Fatal("版本未清除")
	}
}

func TestDeleteSystemPersists(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := policyConfig(&now)
	cfg.DataFile = filepath.Join(t.TempDir(), "state.json")

	svc := NewService(cfg)
	if _, err := svc.Register("SYS-E", "E", []string{"127.0.0.1"}, "", "test", ""); err != nil {
		t.Fatalf("登記失敗：%v", err)
	}
	if err := svc.SetStatus("SYS-E", false, "test", ""); err != nil {
		t.Fatalf("停用失敗：%v", err)
	}
	if err := svc.DeleteSystem("SYS-E", "test", ""); err != nil {
		t.Fatalf("刪除失敗：%v", err)
	}

	reloaded := NewService(cfg)
	for _, s := range reloaded.Systems() {
		if s.Code == "SYS-E" {
			t.Fatal("重新載入後系統仍存在")
		}
	}
}
