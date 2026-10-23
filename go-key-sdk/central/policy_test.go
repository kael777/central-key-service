package central

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func policyConfig(now *time.Time) Config {
	return Config{
		KEK:            bytes.Repeat([]byte{9}, 32),
		AdminToken:     "t",
		Grace:          5 * time.Minute,
		Prepublish:     time.Minute,
		Rotation:       time.Hour,
		RequireIPAllow: true,
		MaxDecrypt:     8,
		Now:            func() time.Time { return *now },
	}
}

// 允許 IP 必填：未填時回 ErrInvalid。
func TestRequireIPAllow(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	svc := NewService(policyConfig(&now))

	if _, err := svc.Register("SYS-A", "A", nil, "", "test", ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("未填 IP 應回 ErrInvalid，實際 %v", err)
	}
	if _, err := svc.Register("SYS-A", "A", []string{"127.0.0.1"}, "", "test", ""); err != nil {
		t.Fatalf("填了 IP 應成功：%v", err)
	}
}

// 5 分鐘內連續輪替，舊版仍保留原本的緩衝期。
func TestGracePreservedAcrossRotations(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	svc := NewService(policyConfig(&now))
	if _, err := svc.Register("SYS-A", "A", []string{"127.0.0.1"}, "", "test", ""); err != nil {
		t.Fatalf("登記失敗：%v", err)
	}

	if _, err := svc.Rotate("SYS-A", "test", ""); err != nil {
		t.Fatalf("第一次輪替失敗：%v", err)
	}
	var deadline time.Time
	for _, v := range svc.Versions("SYS-A") {
		if v.KID == "SYS-A:1" {
			deadline = v.DecryptUntil
		}
	}
	if deadline.IsZero() {
		t.Fatal("第一次輪替後 SYS-A:1 應在 decrypt_only")
	}

	now = now.Add(time.Minute)
	if _, err := svc.Rotate("SYS-A", "test", ""); err != nil {
		t.Fatalf("第二次輪替失敗：%v", err)
	}

	for _, v := range svc.Versions("SYS-A") {
		if v.KID != "SYS-A:1" {
			continue
		}
		if v.State != StateDecryptOnly {
			t.Fatalf("5 分鐘內 SYS-A:1 不應被退役，實際 %s", v.State)
		}
		if !v.DecryptUntil.Equal(deadline) {
			t.Fatalf("緩衝期被縮短：原本 %s，現在 %s", deadline, v.DecryptUntil)
		}
		if _, err := svc.PrivateKey("SYS-A", "SYS-A:1"); err != nil {
			t.Fatalf("緩衝期內應能取得舊私鑰：%v", err)
		}
		return
	}
	t.Fatal("找不到 SYS-A:1")
}
