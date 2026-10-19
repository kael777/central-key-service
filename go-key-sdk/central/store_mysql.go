package central

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// mysqlStore 以 MySQL 作為共享狀態後端，支援多實例部署。
type mysqlStore struct {
	dsn  string
	once sync.Once
	db   *sql.DB
	err  error
}

func (m *mysqlStore) External() bool { return true }

// Describe 只顯示主機與資料庫，不含帳密。
func (m *mysqlStore) Describe() string {
	rest := m.dsn
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		rest = rest[i+1:]
	}
	if i := strings.Index(rest, "?"); i >= 0 {
		rest = rest[:i]
	}
	return "mysql:" + rest
}

func (m *mysqlStore) conn() (*sql.DB, error) {
	m.once.Do(func() {
		db, err := sql.Open("mysql", m.dsn)
		if err != nil {
			m.err = err
			return
		}
		db.SetMaxOpenConns(8)
		db.SetMaxIdleConns(4)
		db.SetConnMaxLifetime(5 * time.Minute)
		if err := db.Ping(); err != nil {
			m.err = fmt.Errorf("連線 MySQL 失敗：%w", err)
			return
		}
		m.db = db
		m.err = EnsureSchema(db)
	})
	return m.db, m.err
}

// EnsureSchema 建立必要資料表；正式環境建議改用 migration 工具管理。
func EnsureSchema(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS systems (
			code        VARCHAR(64)  NOT NULL PRIMARY KEY,
			name        VARCHAR(255) NOT NULL,
			ip_allow    JSON         NULL,
			status      VARCHAR(16)  NOT NULL,
			mode        VARCHAR(16)  NOT NULL,
			note        TEXT         NULL,
			created_at  DATETIME(6)  NOT NULL
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		`CREATE TABLE IF NOT EXISTS key_versions (
			kid              VARCHAR(128) NOT NULL PRIMARY KEY,
			system_code      VARCHAR(64)  NOT NULL,
			seq              INT          NOT NULL,
			alg              VARCHAR(64)  NOT NULL,
			public_key_spki  VARBINARY(256) NOT NULL,
			wrapped_priv     VARBINARY(512) NULL,
			state            VARCHAR(16)  NOT NULL,
			not_before       DATETIME(6)  NOT NULL,
			decrypt_until    DATETIME(6)  NULL,
			created_at       DATETIME(6)  NOT NULL,
			UNIQUE KEY uk_system_seq (system_code, seq),
			KEY idx_system_state (system_code, state)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		`CREATE TABLE IF NOT EXISTS audit_log (
			id           BIGINT AUTO_INCREMENT PRIMARY KEY,
			ts           DATETIME(6) NOT NULL,
			actor        VARCHAR(128) NULL,
			action       VARCHAR(64)  NULL,
			system_code  VARCHAR(64)  NULL,
			kid          VARCHAR(128) NULL,
			src_ip       VARCHAR(64)  NULL,
			result       VARCHAR(32)  NULL,
			KEY idx_ts (ts)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		`CREATE TABLE IF NOT EXISTS service_locks (
			name        VARCHAR(64) NOT NULL PRIMARY KEY,
			owner       VARCHAR(64) NOT NULL,
			expires_at  DATETIME(6) NOT NULL
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			return fmt.Errorf("建立資料表失敗：%w", err)
		}
	}
	return nil
}

func (m *mysqlStore) Load() (*stateData, error) {
	db, err := m.conn()
	if err != nil {
		return nil, err
	}
	out := &stateData{Systems: map[string]*System{}, Versions: map[string][]*KeyVersion{}}

	rows, err := db.Query(`SELECT code, name, ip_allow, status, mode, note, created_at FROM systems`)
	if err != nil {
		return nil, fmt.Errorf("讀取 systems 失敗：%w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			code, name, status, mode string
			ipJSON                   sql.NullString
			note                     sql.NullString
			created                  time.Time
		)
		if err := rows.Scan(&code, &name, &ipJSON, &status, &mode, &note, &created); err != nil {
			return nil, err
		}
		sys := &System{Code: code, Name: name, Status: status, Mode: mode, Note: note.String, CreatedAt: created.UTC()}
		if ipJSON.Valid && ipJSON.String != "" {
			_ = json.Unmarshal([]byte(ipJSON.String), &sys.IPAllow)
		}
		out.Systems[code] = sys
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	vrows, err := db.Query(`SELECT kid, system_code, seq, alg, public_key_spki, wrapped_priv, state, not_before, decrypt_until, created_at
		FROM key_versions ORDER BY system_code, seq`)
	if err != nil {
		return nil, fmt.Errorf("讀取 key_versions 失敗：%w", err)
	}
	defer vrows.Close()
	for vrows.Next() {
		v := &KeyVersion{}
		var decryptUntil sql.NullTime
		var wrapped []byte
		if err := vrows.Scan(&v.KID, &v.SystemCode, &v.Seq, &v.Alg, &v.PublicKeySPKI, &wrapped, &v.State,
			&v.NotBefore, &decryptUntil, &v.CreatedAt); err != nil {
			return nil, err
		}
		v.WrappedPriv = wrapped
		v.NotBefore = v.NotBefore.UTC()
		v.CreatedAt = v.CreatedAt.UTC()
		if decryptUntil.Valid {
			v.DecryptUntil = decryptUntil.Time.UTC()
		}
		out.Versions[v.SystemCode] = append(out.Versions[v.SystemCode], v)
	}
	return out, vrows.Err()
}

func (m *mysqlStore) Save(d *stateData) error {
	db, err := m.conn()
	if err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	for _, sys := range d.Systems {
		ip, _ := json.Marshal(sys.IPAllow)
		_, err := tx.Exec(`INSERT INTO systems (code, name, ip_allow, status, mode, note, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)
			ON DUPLICATE KEY UPDATE name=VALUES(name), ip_allow=VALUES(ip_allow), status=VALUES(status),
			mode=VALUES(mode), note=VALUES(note)`,
			sys.Code, sys.Name, string(ip), sys.Status, sys.Mode, sys.Note, sys.CreatedAt.UTC())
		if err != nil {
			return fmt.Errorf("寫入 systems 失敗：%w", err)
		}
	}
	for _, vs := range d.Versions {
		for _, v := range vs {
			var du any
			if !v.DecryptUntil.IsZero() {
				du = v.DecryptUntil.UTC()
			}
			_, err := tx.Exec(`INSERT INTO key_versions
				(kid, system_code, seq, alg, public_key_spki, wrapped_priv, state, not_before, decrypt_until, created_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON DUPLICATE KEY UPDATE state=VALUES(state), wrapped_priv=VALUES(wrapped_priv),
				decrypt_until=VALUES(decrypt_until), not_before=VALUES(not_before)`,
				v.KID, v.SystemCode, v.Seq, v.Alg, v.PublicKeySPKI, v.WrappedPriv, v.State,
				v.NotBefore.UTC(), du, v.CreatedAt.UTC())
			if err != nil {
				return fmt.Errorf("寫入 key_versions 失敗：%w", err)
			}
		}
	}
	return tx.Commit()
}

func (m *mysqlStore) AppendAudit(e AuditEntry) error {
	db, err := m.conn()
	if err != nil {
		return err
	}
	_, err = db.Exec(`INSERT INTO audit_log (ts, actor, action, system_code, kid, src_ip, result)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		e.TS.UTC(), e.Actor, e.Action, e.System, e.KID, e.IP, e.Result)
	return err
}

// TryLease 以資料列租約實作跨實例互斥（避免依賴連線綁定的 advisory lock）。
func (m *mysqlStore) TryLease(name, owner string, ttl time.Duration) (bool, error) {
	db, err := m.conn()
	if err != nil {
		return false, err
	}
	now := time.Now().UTC()
	expires := now.Add(ttl)
	if _, err := db.Exec(`INSERT INTO service_locks (name, owner, expires_at) VALUES (?, ?, ?)
		ON DUPLICATE KEY UPDATE
			owner = IF(expires_at <= VALUES(expires_at) - INTERVAL ? MICROSECOND, VALUES(owner), owner),
			expires_at = IF(expires_at <= VALUES(expires_at) - INTERVAL ? MICROSECOND, VALUES(expires_at), expires_at)`,
		name, owner, expires, ttl.Microseconds(), ttl.Microseconds()); err != nil {
		return false, err
	}
	var holder string
	if err := db.QueryRow(`SELECT owner FROM service_locks WHERE name = ?`, name).Scan(&holder); err != nil {
		return false, err
	}
	return holder == owner, nil
}

func (m *mysqlStore) Close() error {
	if m.db != nil {
		return m.db.Close()
	}
	return nil
}
