package central

import (
	"bytes"
	"path/filepath"
	"testing"
	"time"
)

func testConfig(now *time.Time) Config {
	return Config{
		KEK:           bytes.Repeat([]byte{7}, 32),
		AdminToken:    "t",
		Grace:         time.Minute,
		Prepublish:    time.Minute,
		Rotation:      time.Hour,
		Retention:     time.Hour,
		RetentionKeep: 1,
		Now:           func() time.Time { return *now },
	}
}

// 建立三個版本：v1、v2 已退役，v3 active。
func seedRetired(t *testing.T, svc *Service, now *time.Time) {
	t.Helper()
	if _, err := svc.Register("SYS-A", "A", nil, "", "test", ""); err != nil {
		t.Fatalf("登記失敗：%v", err)
	}
	if _, err := svc.Rotate("SYS-A", "test", ""); err != nil {
		t.Fatalf("輪替失敗：%v", err)
	}
	*now = now.Add(2 * time.Minute)
	svc.Tick(*now)
	if _, err := svc.Rotate("SYS-A", "test", ""); err != nil {
		t.Fatalf("輪替失敗：%v", err)
	}
	*now = now.Add(2 * time.Minute)
	svc.Tick(*now)
}

func TestPruneRetiredKeepsActiveAndRecent(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	svc := NewService(testConfig(&now))
	seedRetired(t, svc, &now)

	// 兩個退役版本
	if got := len(svc.versions["SYS-A"]); got != 3 {
		t.Fatalf("預期 3 個版本，實際 %d", got)
	}

	now = now.Add(3 * time.Hour)
	n, err := svc.Prune(now)
	if err != nil {
		t.Fatalf("清理失敗：%v", err)
	}
	if n != 1 {
		t.Fatalf("預期刪除 1 個，實際 %d", n)
	}

	kids := map[string]string{}
	for _, v := range svc.versions["SYS-A"] {
		kids[v.KID] = v.State
	}
	if _, ok := kids["SYS-A:1"]; ok {
		t.Fatal("最舊的退役版本應被刪除")
	}
	if state, ok := kids["SYS-A:2"]; !ok || state != StateRetired {
		t.Fatal("依保留數應留下 SYS-A:2")
	}
	if state, ok := kids["SYS-A:3"]; !ok || state != StateActive {
		t.Fatal("active 版本絕不能被刪")
	}
}

func TestPruneSkipsWithinRetention(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	svc := NewService(testConfig(&now))
	seedRetired(t, svc, &now)

	// 只過 30 分鐘，未達 1 小時保留期
	now = now.Add(30 * time.Minute)
	n, err := svc.Prune(now)
	if err != nil {
		t.Fatalf("清理失敗：%v", err)
	}
	if n != 0 {
		t.Fatalf("保留期內不應刪除，實際 %d", n)
	}
}

func TestReloadSkipsRetired(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	cfg := testConfig(&now)
	cfg.DataFile = filepath.Join(dir, "state.json")

	svc := NewService(cfg)
	seedRetired(t, svc, &now)

	// 重新載入：退役版本不應進記憶體
	svc2 := NewService(cfg)
	for _, v := range svc2.versions["SYS-A"] {
		if v.State == StateRetired {
			t.Fatalf("重載後不應含退役版本：%s", v.KID)
		}
	}
	if len(svc2.versions["SYS-A"]) != 1 {
		t.Fatalf("重載後應只剩 active，實際 %d 個", len(svc2.versions["SYS-A"]))
	}
}
