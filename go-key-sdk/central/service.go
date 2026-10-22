package central

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"example.com/key-sdk/keycrypto"
)

// 系統狀態
const (
	StatusEnabled  = "enabled"
	StatusDisabled = "disabled"
)

// 政策模式
const (
	ModeRequired = "required"
	ModeDisabled = "disabled" // 中央明確回傳不加密
)

// 金鑰版本狀態
const (
	StatePending     = "pending"
	StateActive      = "active"
	StateDecryptOnly = "decrypt_only"
	StateRetired     = "retired"
)

var (
	ErrNotFound    = errors.New("not found")
	ErrConflict    = errors.New("conflict")
	ErrUnavailable = errors.New("unavailable")
)

// System 是接入系統的登記資料。
type System struct {
	Code      string    `json:"code"`
	Name      string    `json:"name"`
	IPAllow   []string  `json:"ip_allow"` // CIDR 或單一 IP
	Status    string    `json:"status"`
	Mode      string    `json:"mode"`
	Note      string    `json:"note"`
	CreatedAt time.Time `json:"created_at"`
	NextSeq   int       `json:"next_seq"`
}

// KeyVersion 是一個金鑰版本。私鑰以 KEK 包裝後存放，記憶體與檔案皆無明文。
type KeyVersion struct {
	KID           string    `json:"kid"`
	SystemCode    string    `json:"system_code"`
	Seq           int       `json:"seq"`
	Alg           string    `json:"alg"`
	PublicKeySPKI []byte    `json:"public_key_spki"`
	WrappedPriv   []byte    `json:"-"`
	State         string    `json:"state"`
	NotBefore     time.Time `json:"not_before"`
	DecryptUntil  time.Time `json:"decrypt_until"`
	CreatedAt     time.Time `json:"created_at"`
}

// AuditEntry 只記識別資訊，永不記錄私鑰或明文。
type AuditEntry struct {
	TS     time.Time `json:"ts"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	System string    `json:"system"`
	KID    string    `json:"kid,omitempty"`
	IP     string    `json:"ip,omitempty"`
	Result string    `json:"result"`
}

// Config 是服務設定。Grace 是舊版解密緩衝期。
type Config struct {
	Grace          time.Duration // 新舊版並存時間，正式環境 5m
	Prepublish     time.Duration // 新公鑰提前發布
	Rotation       time.Duration // 自動輪替週期
	Retention      time.Duration // 退役版本保留時間
	RetentionKeep  int           // 每系統至少保留的退役版本數
	RefreshTTL     time.Duration // 多實例讀取重載的最小間隔
	KEK            []byte        // 32 bytes，包裝私鑰用
	AdminToken     string
	AdminUser      string            // 後台頁面 Basic Auth 帳號，預設 admin
	SignKey        *ecdsa.PrivateKey // 對不加密政策簽章（可為 nil）
	SessionSecret  string            // 簽章 cookie 用；留空則用 AdminToken
	APIAdminToken  string            // 管理 API 權杖；留空則用 AdminToken
	AdminCIDR      []string          // 後台允許來源網段；空表示不限制
	TrustedProxies []string          // 受信反向代理網段（Nginx）
	ProxySecret    string            // 代理轉發身分時必須帶的共享密鑰
	OIDC           *OIDCConfig       // 非 nil 時啟用 SSO
	DataFile       string            // 非空則持久化到 JSON 檔
	AuditFile      string            // 非空則追加 JSONL
	DSN            string            // 非空則使用 MySQL（優先於 DataFile）
	Now            func() time.Time
}

// Counters 是 /metrics 的來源。
type Counters struct {
	SyncOK      int64
	SyncNotMod  int64
	SyncDenied  int64
	PrivIssued  int64
	PrivDenied  int64
	Rotations   int64
	AuthFailure int64
}

// Service 是中央 KEY 服務的核心，所有狀態由單一 mutex 保護。
type Service struct {
	mu       sync.Mutex
	cfg      Config
	systems  map[string]*System
	versions map[string][]*KeyVersion // 每個系統的版本，依 Seq 遞增
	audit    []AuditEntry
	counters Counters
	now      func() time.Time
	store    Store

	lastRefresh time.Time
	lastPrune   time.Time
}

// NewService 建立服務；cfg.Grace 為 0 時採 5 分鐘。
func NewService(cfg Config) *Service {
	if cfg.Retention == 0 {
		cfg.Retention = 720 * time.Hour
	}
	if cfg.RetentionKeep == 0 {
		cfg.RetentionKeep = 20
	}
	if cfg.RefreshTTL == 0 {
		cfg.RefreshTTL = time.Second
	}
	if cfg.Grace == 0 {
		cfg.Grace = 5 * time.Minute
	}
	if cfg.Prepublish == 0 {
		cfg.Prepublish = 10 * time.Minute
	}
	if cfg.Rotation == 0 {
		cfg.Rotation = 30 * 24 * time.Hour
	}
	if len(cfg.KEK) == 0 {
		sum := sha256.Sum256([]byte("dev-insecure-kek"))
		cfg.KEK = sum[:]
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	s := &Service{
		cfg:      cfg,
		systems:  map[string]*System{},
		versions: map[string][]*KeyVersion{},
		now:      now,
	}
	s.store = newStore(cfg)
	// 不論哪種後端都要載入既有狀態（檔案後端最容易漏，會導致重啟後被清空）。
	if d, err := s.store.Load(); err != nil {
		log.Printf("載入儲存失敗：%v", err)
	} else if d != nil {
		s.systems, s.versions = d.Systems, d.Versions
	}
	return s
}

// refreshLocked 在外部儲存模式下重新載入狀態，避免多實例互相覆蓋。
// maybeRefreshLocked 依 TTL 決定是否重載，避免每次讀取都全量查庫。
func (s *Service) maybeRefreshLocked() {
	if !s.store.External() || s.now().Sub(s.lastRefresh) < s.cfg.RefreshTTL {
		return
	}
	s.refreshLocked()
}

func (s *Service) refreshLocked() {
	s.lastRefresh = s.now()
	if !s.store.External() {
		return
	}
	d, err := s.store.Load()
	if err != nil {
		log.Printf("重新載入狀態失敗：%v", err)
		return
	}
	if d != nil {
		s.systems, s.versions = d.Systems, d.Versions
	}
}

// ---------- 系統登記 ----------

// Register 建立系統並立即產生第一版金鑰（需求：新增並啟用後自動建鑰）。
func (s *Service) Register(code, name string, ips []string, note, actor, ip string) (*System, error) {
	code = strings.TrimSpace(code)
	if !keycrypto.ValidKID(code + ":1") {
		return nil, fmt.Errorf("系統代碼格式非法：%q", code)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked()
	if _, ok := s.systems[code]; ok {
		return nil, fmt.Errorf("%w: 系統 %s 已存在", ErrConflict, code)
	}
	for _, c := range ips {
		if err := ValidHostSpec(c); err != nil {
			return nil, fmt.Errorf("允許 IP 格式非法：%q", c)
		}
	}
	sys := &System{
		Code: code, Name: name, IPAllow: ips, Status: StatusEnabled,
		Mode: ModeRequired, Note: note, CreatedAt: s.now(),
	}
	s.systems[code] = sys
	if _, err := s.createVersionLocked(code, s.now(), StateActive); err != nil {
		delete(s.systems, code)
		return nil, err
	}
	s.auditLocked(AuditEntry{TS: s.now(), Actor: actor, Action: "system.register", System: code, IP: ip, Result: "ok"})
	return sys, s.saveLocked()
}

// UpdateSystem 更新名稱、IP 白名單、備註與政策模式。
func (s *Service) UpdateSystem(code, name string, ips []string, note, mode, actor, ip string) (*System, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sys, ok := s.systems[code]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, code)
	}
	for _, c := range ips {
		if err := ValidHostSpec(c); err != nil {
			return nil, fmt.Errorf("允許 IP 格式非法：%q", c)
		}
	}
	if mode != "" && mode != ModeRequired && mode != ModeDisabled {
		return nil, fmt.Errorf("政策模式非法：%q", mode)
	}
	if name != "" {
		sys.Name = name
	}
	sys.IPAllow = ips
	sys.Note = note
	if mode != "" {
		sys.Mode = mode
	}
	s.auditLocked(AuditEntry{TS: s.now(), Actor: actor, Action: "system.update", System: code, IP: ip, Result: "ok"})
	return sys, s.saveLocked()
}

// SetStatus 啟用／停用。停用即作廢現行金鑰對；重新啟用產生全新金鑰對。
func (s *Service) SetStatus(code string, enabled bool, actor, ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sys, ok := s.systems[code]
	if !ok {
		return fmt.Errorf("%w: %s", ErrNotFound, code)
	}
	now := s.now()
	if enabled {
		if sys.Status == StatusEnabled {
			return nil
		}
		sys.Status = StatusEnabled
		if _, err := s.createVersionLocked(code, now, StateActive); err != nil {
			return err
		}
		s.auditLocked(AuditEntry{TS: now, Actor: actor, Action: "system.enable", System: code, IP: ip, Result: "ok"})
	} else {
		if sys.Status == StatusDisabled {
			return nil
		}
		sys.Status = StatusDisabled
		// 立即作廢所有未退役版本
		for _, v := range s.versions[code] {
			if v.State != StateRetired {
				v.State = StateRetired
				v.WrappedPriv = nil
			}
		}
		s.auditLocked(AuditEntry{TS: now, Actor: actor, Action: "system.disable", System: code, IP: ip, Result: "ok"})
	}
	return s.saveLocked()
}

// Rotate 立即產生新版本：舊版進入 decrypt_only，Grace 後退役。
// Rotate 立即輪替：舊版進入 decrypt_only，Grace 後退役。
func (s *Service) Rotate(code, actor, ip string) (*KeyVersion, error) {
	unlock, err := s.store.LockSystem(code, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked()
	sys, ok := s.systems[code]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, code)
	}
	if sys.Status != StatusEnabled {
		return nil, fmt.Errorf("%w: 系統已停用", ErrConflict)
	}
	now := s.now()
	nv, err := s.rotateLocked(code, now)
	if err != nil {
		return nil, err
	}
	s.counters.Rotations++
	s.auditLocked(AuditEntry{TS: now, Actor: actor, Action: "key.rotate", System: code, KID: nv.KID, IP: ip, Result: "ok"})
	return nv, nil
}

// rotateLocked 只做狀態轉移與新版本建立，不負責鎖、稽核與存檔。
func (s *Service) rotateLocked(code string, now time.Time) (*KeyVersion, error) {
	for _, v := range s.versions[code] {
		switch v.State {
		case StateActive:
			v.State = StateDecryptOnly
			v.DecryptUntil = now.Add(s.cfg.Grace)
		case StateDecryptOnly:
			// 連續輪替時立即退役更舊的版本，確保白名單最多 2 個
			v.State = StateRetired
			v.WrappedPriv = nil
		}
	}
	return s.createVersionLocked(code, now, StateActive)
}

// ScheduleRotate 建立待生效版本（pending），於 prepublish 後由 Tick 轉為 active。
func (s *Service) ScheduleRotate(code, actor, ip string) (*KeyVersion, error) {
	unlock, err := s.store.LockSystem(code, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked()
	sys, ok := s.systems[code]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, code)
	}
	if sys.Status != StatusEnabled {
		return nil, fmt.Errorf("%w: 系統已停用", ErrConflict)
	}
	now := s.now()
	nv, err := s.createVersionLocked(code, now.Add(s.cfg.Prepublish), StatePending)
	if err != nil {
		return nil, err
	}
	s.auditLocked(AuditEntry{TS: now, Actor: actor, Action: "key.schedule-rotate", System: code, KID: nv.KID, IP: ip, Result: "ok"})
	return nv, s.saveLocked()
}

// Tick 推進版本狀態，由排程器每秒呼叫；測試可直接傳入時間。
// Versions 回傳指定系統的所有版本（含退役狀態，僅供管理介面）。
func (s *Service) Versions(code string) []*KeyVersion {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maybeRefreshLocked()
	out := make([]*KeyVersion, 0, len(s.versions[code]))
	out = append(out, s.versions[code]...)
	return out
}

// Prune 刪除超過保留期且超出每系統保留數的退役版本。
func (s *Service) Prune(now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pruneLocked(now)
}

func (s *Service) pruneLocked(now time.Time) (int, error) {
	cutoff := now.Add(-s.cfg.Retention)
	var removed []string
	for code, list := range s.versions {
		var retired []*KeyVersion
		for _, v := range list {
			if v.State == StateRetired {
				retired = append(retired, v)
			}
		}
		if len(retired) == 0 {
			continue
		}
		sort.Slice(retired, func(i, j int) bool { return retired[i].Seq > retired[j].Seq })
		drop := map[string]bool{}
		for i, v := range retired {
			if i < s.cfg.RetentionKeep {
				continue
			}
			if v.CreatedAt.Before(cutoff) {
				drop[v.KID] = true
				removed = append(removed, v.KID)
			}
		}
		if len(drop) == 0 {
			continue
		}
		kept := list[:0]
		for _, v := range list {
			if !drop[v.KID] {
				kept = append(kept, v)
			}
		}
		s.versions[code] = kept
	}
	if len(removed) == 0 {
		return 0, nil
	}
	if err := s.store.DeleteVersions(removed); err != nil {
		return 0, err
	}
	return len(removed), s.saveLocked()
}

func (s *Service) Tick(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastPrune.IsZero() {
		s.lastPrune = now
	} else if now.Sub(s.lastPrune) >= time.Hour {
		s.lastPrune = now
		if n, err := s.pruneLocked(now); err != nil {
			log.Printf("清理退役版本失敗：%v", err)
		} else if n > 0 {
			log.Printf("清理退役版本 %d 個", n)
		}
	}
	changed := false
	for _, vs := range s.versions {
		for _, v := range vs {
			switch v.State {
			case StatePending:
				if !now.Before(v.NotBefore) {
					for _, o := range vs {
						if o == v {
							continue
						}
						switch o.State {
						case StateActive:
							o.State = StateDecryptOnly
							o.DecryptUntil = now.Add(s.cfg.Grace)
							changed = true
						case StateDecryptOnly:
							o.State = StateRetired
							o.WrappedPriv = nil
							changed = true
						}
					}
					v.State = StateActive
					changed = true
				}
			case StateDecryptOnly:
				if !v.DecryptUntil.IsZero() && !now.Before(v.DecryptUntil) {
					v.State = StateRetired
					v.WrappedPriv = nil
					changed = true
				}
			}
		}
	}
	if changed {
		_ = s.saveLocked()
	}
}

// ---------- 對外查詢 ----------

// VersionRef 是下發給用戶端的版本描述。
type VersionRef struct {
	KID          string `json:"kid"`
	Alg          string `json:"alg,omitempty"`
	PublicKey    string `json:"public_key,omitempty"`
	NotBefore    string `json:"not_before,omitempty"`
	DecryptUntil string `json:"decrypt_until,omitempty"`
}

// SyncSnapshot 是 /sync 的回應內容。
type SyncSnapshot struct {
	ServerTime      time.Time             `json:"server_time"`
	SystemCode      string                `json:"system_code"`
	Mode            string                `json:"mode"`
	PolicyID        string                `json:"policy_id"`
	PolicyExpiresAt string                `json:"policy_expires_at,omitempty"`
	PolicySignature string                `json:"policy_signature,omitempty"`
	DecryptVersions []VersionRef          `json:"decrypt_versions"`
	Peers           map[string]VersionRef `json:"peers"`
	Next            map[string]VersionRef `json:"next,omitempty"`
}

// Sync 產生該系統的原子快照。呼叫前需先 Tick。
func (s *Service) Sync(code string) (*SyncSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maybeRefreshLocked()
	return s.syncLocked(code)
}

func (s *Service) syncLocked(code string) (*SyncSnapshot, error) {
	sys, ok := s.systems[code]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, code)
	}
	if sys.Status != StatusEnabled {
		return nil, fmt.Errorf("%w: 系統已停用", ErrForbidden)
	}
	now := s.now()
	snap := &SyncSnapshot{
		ServerTime: now.UTC(),
		SystemCode: code,
		Mode:       sys.Mode,
		PolicyID:   "p-" + code,
		Peers:      map[string]VersionRef{},
	}
	if sys.Mode == ModeDisabled {
		snap.PolicyExpiresAt = now.Add(24 * time.Hour).UTC().Format(time.RFC3339)
		snap.PolicySignature = s.signPolicy(code, snap.PolicyExpiresAt)
	}
	for _, v := range s.versions[code] {
		switch v.State {
		case StateActive:
			snap.DecryptVersions = append(snap.DecryptVersions, VersionRef{KID: v.KID, Alg: v.Alg, NotBefore: v.NotBefore.UTC().Format(time.RFC3339)})
		case StateDecryptOnly:
			snap.DecryptVersions = append(snap.DecryptVersions, VersionRef{KID: v.KID, Alg: v.Alg, NotBefore: v.NotBefore.UTC().Format(time.RFC3339), DecryptUntil: v.DecryptUntil.UTC().Format(time.RFC3339)})
		}
	}
	sort.Slice(snap.DecryptVersions, func(i, j int) bool { return snap.DecryptVersions[i].KID > snap.DecryptVersions[j].KID })
	for other, o := range s.systems {
		if other == code || o.Status != StatusEnabled {
			continue
		}
		for _, v := range s.versions[other] {
			switch v.State {
			case StateActive:
				snap.Peers[other] = VersionRef{
					KID:       v.KID,
					Alg:       v.Alg,
					PublicKey: base64.StdEncoding.EncodeToString(v.PublicKeySPKI),
					NotBefore: v.NotBefore.UTC().Format(time.RFC3339),
				}
			case StatePending:
				if snap.Next == nil {
					snap.Next = map[string]VersionRef{}
				}
				snap.Next[other] = VersionRef{
					KID:       v.KID,
					Alg:       v.Alg,
					PublicKey: base64.StdEncoding.EncodeToString(v.PublicKeySPKI),
					NotBefore: v.NotBefore.UTC().Format(time.RFC3339),
				}
			}
		}
	}
	return snap, nil
}

// ErrForbidden 表示授權不符。
var ErrForbidden = errors.New("forbidden")

// PrivateKey 回傳 PKCS8 私鑰 DER。只有 active 或仍在緩衝期的 decrypt_only 可取得。
func (s *Service) PrivateKey(code, kid string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maybeRefreshLocked()
	sys, ok := s.systems[code]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, code)
	}
	if sys.Status != StatusEnabled {
		return nil, fmt.Errorf("%w: 系統已停用", ErrForbidden)
	}
	// kid 前綴不屬於本系統即拒絕，避免洩漏其他系統是否存在該版本
	if owner, _, ok := strings.Cut(kid, ":"); ok && owner != code {
		return nil, fmt.Errorf("%w: kid 不屬於 %s", ErrForbidden, code)
	}
	for _, v := range s.versions[code] {
		if v.KID != kid {
			continue
		}
		if v.State != StateActive && v.State != StateDecryptOnly && v.State != StatePending {
			return nil, fmt.Errorf("%w: 版本 %s 狀態為 %s", ErrForbidden, kid, v.State)
		}
		if v.State == StateDecryptOnly && !s.now().Before(v.DecryptUntil) {
			return nil, fmt.Errorf("%w: 版本 %s 已超過緩衝期", ErrForbidden, kid)
		}
		if len(v.WrappedPriv) == 0 {
			return nil, fmt.Errorf("%w: 版本 %s 私鑰已銷毀", ErrNotFound, kid)
		}
		scalar, err := s.unwrap(v.WrappedPriv)
		if err != nil {
			return nil, err
		}
		priv, err := ecdh.P256().NewPrivateKey(scalar)
		if err != nil {
			return nil, err
		}
		return marshalPKCS8(priv)
	}
	return nil, fmt.Errorf("%w: %s", ErrNotFound, kid)
}

// Systems 回傳所有系統（依代碼排序）。
func (s *Service) Systems() []System {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]System, 0, len(s.systems))
	for _, v := range s.systems {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out
}

// System 取得單一系統資料。
func (s *Service) System(code string) (*System, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sys, ok := s.systems[code]
	if !ok {
		return nil, false
	}
	c := *sys
	return &c, true
}

// VersionsOf 回傳某系統的版本（依 Seq）。
func (s *Service) VersionsOf(code string) []KeyVersion {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]KeyVersion, 0, len(s.versions[code]))
	for _, v := range s.versions[code] {
		out = append(out, *v)
	}
	return out
}

// Audit 回傳稽核紀錄（最多最後 n 筆，n<=0 表示全部）。
func (s *Service) Audit(n int) []AuditEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.audit
	if n > 0 && len(a) > n {
		a = a[len(a)-n:]
	}
	out := make([]AuditEntry, len(a))
	copy(out, a)
	return out
}

// Metrics 回傳統計。
func (s *Service) Metrics() (Counters, int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	enabled := 0
	for _, sys := range s.systems {
		if sys.Status == StatusEnabled {
			enabled++
		}
	}
	return s.counters, len(s.systems), enabled
}

// CheckIP 驗證來源 IP 是否符合白名單（空清單代表不限制）。
func (s *Service) CheckIP(code, remote string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	sys, ok := s.systems[code]
	if !ok {
		// 多實例下，別台剛登記的系統本地還沒有：刷新一次再判斷，
		// 避免鑑權階段就回 403（那條路徑不會再進 Sync 觸發刷新）。
		s.maybeRefreshLocked()
		sys, ok = s.systems[code]
	}
	if !ok {
		return false
	}
	if len(sys.IPAllow) == 0 {
		return true
	}
	return HostAllowed(sys.IPAllow, remote)
}

// ActiveKID 回傳系統現行版本識別碼。
func (s *Service) ActiveKID(code string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range s.versions[code] {
		if v.State == StateActive {
			return v.KID
		}
	}
	return ""
}

// ---------- 內部 ----------

func (s *Service) createVersionLocked(code string, notBefore time.Time, state string) (*KeyVersion, error) {
	seq := 1
	useMemory := !s.store.External()
	if s.store.External() {
		// 多實例：由資料庫原子取號，避免兩個實例算出同一個 seq。
		n, err := s.store.NextSeq(code)
		if err == nil {
			seq = n
		} else if errors.Is(err, ErrNotFound) {
			// 系統剛登記、尚未寫入資料表：先用記憶體序號，稍後由 saveLocked 落庫。
			useMemory = true
		} else {
			return nil, err
		}
	}
	if useMemory {
		if sys := s.systems[code]; sys != nil {
			if sys.NextSeq >= 1 {
				seq = sys.NextSeq
			} else {
				for _, v := range s.versions[code] {
					if v.Seq >= seq {
						seq = v.Seq + 1
					}
				}
			}
			sys.NextSeq = seq + 1
		}
	}
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	spki, err := keycrypto.SPKIFromECDH(priv.PublicKey())
	if err != nil {
		return nil, err
	}
	wrapped, err := s.wrap(priv.Bytes())
	if err != nil {
		return nil, err
	}
	v := &KeyVersion{
		KID:           fmt.Sprintf("%s:%d", code, seq),
		SystemCode:    code,
		Seq:           seq,
		Alg:           "ECIES-P256-AES256GCM",
		PublicKeySPKI: spki,
		WrappedPriv:   wrapped,
		State:         state,
		NotBefore:     notBefore,
		CreatedAt:     s.now(),
	}
	s.versions[code] = append(s.versions[code], v)
	return v, nil
}

func (s *Service) wrap(plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.cfg.KEK)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return append(nonce, aead.Seal(nil, nonce, plain, nil)...), nil
}

func (s *Service) unwrap(wrapped []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.cfg.KEK)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(wrapped) < aead.NonceSize() {
		return nil, errors.New("包裝私鑰長度不足")
	}
	nonce, ct := wrapped[:aead.NonceSize()], wrapped[aead.NonceSize():]
	return aead.Open(nil, nonce, ct, nil)
}

func (s *Service) signPolicy(code, expiresAt string) string {
	if s.cfg.SignKey == nil {
		return ""
	}
	h := sha256.Sum256([]byte("cms-policy|" + code + "|disabled|" + expiresAt))
	sig, err := ecdsa.SignASN1(rand.Reader, s.cfg.SignKey, h[:])
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(sig)
}

func (s *Service) auditLocked(e AuditEntry) {
	s.audit = append(s.audit, e)
	if len(s.audit) > 10000 {
		s.audit = s.audit[len(s.audit)-10000:]
	}
	if err := s.store.AppendAudit(e); err != nil {
		log.Printf("寫入稽核失敗：%v", err)
	}
}

// persistedVersion 是落盤格式；與 API 格式分離，避免私鑰欄位被序列化到回應。
type persistedVersion struct {
	KID           string    `json:"kid"`
	SystemCode    string    `json:"system_code"`
	Seq           int       `json:"seq"`
	Alg           string    `json:"alg"`
	PublicKeySPKI []byte    `json:"public_key_spki"`
	WrappedPriv   []byte    `json:"wrapped_priv"`
	State         string    `json:"state"`
	NotBefore     time.Time `json:"not_before"`
	DecryptUntil  time.Time `json:"decrypt_until"`
	CreatedAt     time.Time `json:"created_at"`
}

type stateFile struct {
	Systems  map[string]*System             `json:"systems"`
	Versions map[string][]*persistedVersion `json:"versions"`
}

func toPersisted(v *KeyVersion) *persistedVersion {
	return &persistedVersion{
		KID: v.KID, SystemCode: v.SystemCode, Seq: v.Seq, Alg: v.Alg,
		PublicKeySPKI: v.PublicKeySPKI, WrappedPriv: v.WrappedPriv, State: v.State,
		NotBefore: v.NotBefore, DecryptUntil: v.DecryptUntil, CreatedAt: v.CreatedAt,
	}
}

func fromPersisted(p *persistedVersion) *KeyVersion {
	return &KeyVersion{
		KID: p.KID, SystemCode: p.SystemCode, Seq: p.Seq, Alg: p.Alg,
		PublicKeySPKI: p.PublicKeySPKI, WrappedPriv: p.WrappedPriv, State: p.State,
		NotBefore: p.NotBefore, DecryptUntil: p.DecryptUntil, CreatedAt: p.CreatedAt,
	}
}

func (s *Service) saveLocked() error {
	return s.store.Save(&stateData{Systems: s.systems, Versions: s.versions})
}

// StoreInfo 回傳目前使用的儲存後端描述（不含機密）。
func (s *Service) StoreInfo() string { return s.store.Describe() }

// Close 釋放儲存資源。
func (s *Service) Close() error { return s.store.Close() }

// AutoRotate 依 Rotation 週期輪替到期的系統；多實例時以租約互斥。
func (s *Service) AutoRotate(now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked()

	owner := fmt.Sprintf("%d", os.Getpid())
	ok, err := s.store.TryLease("rotation", owner, 2*time.Minute)
	if err != nil || !ok {
		return 0, err
	}

	count := 0
	for code, sys := range s.systems {
		if sys.Status != StatusEnabled {
			continue
		}
		var active *KeyVersion
		pending := false
		for _, v := range s.versions[code] {
			switch v.State {
			case StateActive:
				if active == nil || v.NotBefore.After(active.NotBefore) {
					active = v
				}
			case StatePending:
				pending = true
			}
		}
		// 已有待生效版本就不要重複排程
		if pending || active == nil || now.Sub(active.NotBefore) < s.cfg.Rotation {
			continue
		}
		nv, err := s.createVersionLocked(code, now.Add(s.cfg.Prepublish), StatePending)
		if err != nil {
			log.Printf("排程輪替 %s 失敗：%v", code, err)
			continue
		}
		s.counters.Rotations++
		s.auditLocked(AuditEntry{TS: now, Actor: "scheduler", Action: "key.schedule-rotate", System: code, KID: nv.KID,
			Result: fmt.Sprintf("activate_at=%s", nv.NotBefore.UTC().Format(time.RFC3339))})
		count++
	}
	if count > 0 {
		return count, s.saveLocked()
	}
	return 0, nil
}
func marshalPKCS8(priv *ecdh.PrivateKey) ([]byte, error) {
	raw := priv.PublicKey().Bytes()
	if len(raw) != 65 {
		return nil, errors.New("公鑰長度異常")
	}
	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(raw[1:33]),
		Y:     new(big.Int).SetBytes(raw[33:65]),
	}
	key := &ecdsa.PrivateKey{
		PublicKey: *pub,
		D:         new(big.Int).SetBytes(priv.Bytes()),
	}
	return x509.MarshalPKCS8PrivateKey(key)
}

// hexKey 把十六進位 KEK 轉為 bytes。
func hexKey(s string) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("KEK 需為 32 bytes，實際 %d", len(b))
	}
	return b, nil
}

// HexKey 匯出給 cmd 使用。
func HexKey(s string) ([]byte, error) { return hexKey(s) }

// AuditLogin 記錄後台登入／登出，actor 為實際使用者。
func (s *Service) AuditLogin(user, method, ip, result string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auditLocked(AuditEntry{TS: s.now(), Actor: user, Action: "admin.login." + method, IP: ip, Result: result})
}
