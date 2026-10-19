package central

import (
	"encoding/json"
	"os"
	"time"
)

// stateData 是服務的完整狀態，Store 負責載入與儲存。
type stateData struct {
	Systems  map[string]*System
	Versions map[string][]*KeyVersion
}

// Store 抽象儲存後端。目前有三種：記憶體、JSON 檔、MySQL。
type Store interface {
	// External 表示狀態由外部共享，寫入前需重新載入以避免多實例覆蓋。
	External() bool
	Load() (*stateData, error)
	Save(*stateData) error
	AppendAudit(AuditEntry) error
	// TryLease 取得具名租約，用於多實例下的輪替排程互斥。
	TryLease(name, owner string, ttl time.Duration) (bool, error)
	Close() error
}

func newStore(cfg Config) Store {
	if cfg.DSN != "" {
		return &mysqlStore{dsn: cfg.DSN}
	}
	if cfg.DataFile != "" {
		return &fileStore{path: cfg.DataFile, auditPath: cfg.AuditFile}
	}
	return &memoryStore{auditPath: cfg.AuditFile}
}

// ---------- 記憶體 ----------

type memoryStore struct {
	auditPath string
}

func (m *memoryStore) External() bool                                       { return false }
func (m *memoryStore) Load() (*stateData, error)                            { return nil, nil }
func (m *memoryStore) Save(*stateData) error                                { return nil }
func (m *memoryStore) Close() error                                         { return nil }
func (m *memoryStore) TryLease(string, string, time.Duration) (bool, error) { return true, nil }

func (m *memoryStore) AppendAudit(e AuditEntry) error {
	return appendAuditFile(m.auditPath, e)
}

// ---------- JSON 檔案 ----------

type fileStore struct {
	path      string
	auditPath string
}

func (f *fileStore) External() bool { return false }

func (f *fileStore) Load() (*stateData, error) {
	b, err := os.ReadFile(f.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var st stateFile
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, err
	}
	out := &stateData{Systems: map[string]*System{}, Versions: map[string][]*KeyVersion{}}
	if st.Systems != nil {
		out.Systems = st.Systems
	}
	for code, vs := range st.Versions {
		for _, p := range vs {
			out.Versions[code] = append(out.Versions[code], fromPersisted(p))
		}
	}
	return out, nil
}

func (f *fileStore) Save(d *stateData) error {
	pv := make(map[string][]*persistedVersion, len(d.Versions))
	for code, vs := range d.Versions {
		for _, v := range vs {
			pv[code] = append(pv[code], toPersisted(v))
		}
	}
	b, err := json.MarshalIndent(stateFile{Systems: d.Systems, Versions: pv}, "", "  ")
	if err != nil {
		return err
	}
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, f.path)
}

func (f *fileStore) AppendAudit(e AuditEntry) error { return appendAuditFile(f.auditPath, e) }

func (f *fileStore) TryLease(string, string, time.Duration) (bool, error) { return true, nil }

func (f *fileStore) Close() error { return nil }

func appendAuditFile(path string, e AuditEntry) error {
	if path == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	return err
}
