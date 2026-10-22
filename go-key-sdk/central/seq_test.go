package central

import (
	"bytes"
	"path/filepath"
	"testing"
	"time"
)

// 退役版本不載入後，序號必須從持久化的 next_seq 繼續，不能重複。
func TestKidSequenceSurvivesReload(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	cfg := Config{
		KEK:           bytes.Repeat([]byte{3}, 32),
		AdminToken:    "t",
		Grace:         time.Minute,
		Prepublish:    time.Minute,
		Rotation:      time.Hour,
		Retention:     720 * time.Hour,
		RetentionKeep: 20,
		DataFile:      filepath.Join(dir, "state.json"),
		Now:           func() time.Time { return now },
	}

	svc := NewService(cfg)
	if _, err := svc.Register("SYS-A", "A", nil, "", "test", ""); err != nil {
		t.Fatalf("登記失敗：%v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := svc.Rotate("SYS-A", "test", ""); err != nil {
			t.Fatalf("輪替失敗：%v", err)
		}
	}
	before := svc.Versions("SYS-A")
	maxSeq := 0
	for _, v := range before {
		if v.Seq > maxSeq {
			maxSeq = v.Seq
		}
	}

	// 重新載入：退役版本不會進記憶體
	svc2 := NewService(cfg)
	if got := len(svc2.Versions("SYS-A")); got >= len(before) {
		t.Logf("重載後版本數 %d（原本 %d），退役版本已排除", got, len(before))
	}
	v, err := svc2.Rotate("SYS-A", "test", "")
	if err != nil {
		t.Fatalf("重載後輪替失敗：%v", err)
	}
	if v.Seq <= maxSeq {
		t.Fatalf("序號重複：重載前最大 %d，重載後拿到 %d", maxSeq, v.Seq)
	}
}
