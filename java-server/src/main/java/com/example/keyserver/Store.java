package com.example.keyserver;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Repository
public class Store {

    private final JdbcTemplate jdbc;
    private final ObjectMapper json = new ObjectMapper();

    public Store(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public String info() {
        try {
            String url = jdbc.getDataSource().getConnection().getMetaData().getURL();
            return "mysql:" + url.replaceAll("^jdbc:mysql://", "").replaceAll("\\?.*$", "");
        } catch (Exception e) {
            return "mysql:unknown";
        }
    }

    public void ensureSchema() {
        jdbc.execute("""
                CREATE TABLE IF NOT EXISTS systems (
                  code VARCHAR(64) PRIMARY KEY,
                  name VARCHAR(128) NOT NULL,
                  ip_allow TEXT NOT NULL,
                  status VARCHAR(16) NOT NULL,
                  mode VARCHAR(16) NOT NULL,
                  note VARCHAR(512) NOT NULL DEFAULT '',
                  created_at DATETIME(6) NOT NULL
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """);
        jdbc.execute("""
                CREATE TABLE IF NOT EXISTS key_versions (
                  kid VARCHAR(96) PRIMARY KEY,
                  system_code VARCHAR(64) NOT NULL,
                  seq INT NOT NULL,
                  alg VARCHAR(64) NOT NULL,
                  public_key BLOB NOT NULL,
                  wrapped_priv BLOB NULL,
                  state VARCHAR(16) NOT NULL,
                  not_before DATETIME(6) NOT NULL,
                  decrypt_until DATETIME(6) NULL,
                  created_at DATETIME(6) NOT NULL,
                  KEY idx_system (system_code, seq)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """);
        jdbc.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                  id BIGINT AUTO_INCREMENT PRIMARY KEY,
                  ts DATETIME(6) NOT NULL,
                  actor VARCHAR(128) NOT NULL,
                  action VARCHAR(64) NOT NULL,
                  system_code VARCHAR(64) NOT NULL,
                  kid VARCHAR(96) NOT NULL,
                  ip VARCHAR(64) NOT NULL,
                  result VARCHAR(256) NOT NULL,
                  KEY idx_ts (ts)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """);
        jdbc.execute("""
                CREATE TABLE IF NOT EXISTS service_locks (
                  name VARCHAR(64) PRIMARY KEY,
                  owner VARCHAR(128) NOT NULL,
                  expires_at DATETIME(6) NOT NULL
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """);
    }

    public List<Model.SystemRec> loadSystems() {
        return jdbc.query("SELECT code,name,ip_allow,status,mode,note,created_at FROM systems", (rs, i) -> {
            Model.SystemRec s = new Model.SystemRec();
            s.code = rs.getString("code");
            s.name = rs.getString("name");
            s.ipAllow = parseList(rs.getString("ip_allow"));
            s.status = rs.getString("status");
            s.mode = rs.getString("mode");
            s.note = rs.getString("note");
            s.createdAt = toInstant(rs.getTimestamp("created_at"));
            return s;
        });
    }

    public List<Model.KeyVersion> loadVersions() {
        return jdbc.query("SELECT kid,system_code,seq,alg,public_key,wrapped_priv,state,not_before,decrypt_until,created_at FROM key_versions WHERE state <> 'retired'", (rs, i) -> {
            Model.KeyVersion v = new Model.KeyVersion();
            v.kid = rs.getString("kid");
            v.code = rs.getString("system_code");
            v.seq = rs.getInt("seq");
            v.alg = rs.getString("alg");
            v.spki = rs.getBytes("public_key");
            v.wrapped = rs.getBytes("wrapped_priv");
            v.state = rs.getString("state");
            v.notBefore = toInstant(rs.getTimestamp("not_before"));
            v.decryptUntil = rs.getTimestamp("decrypt_until") == null ? null : toInstant(rs.getTimestamp("decrypt_until"));
            v.createdAt = toInstant(rs.getTimestamp("created_at"));
            return v;
        });
    }

    /** 刪除超過保留期且超出每系統保留數的退役版本，回傳刪除數。 */
    public int pruneRetired(long retentionSeconds, int keepPerSystem) {
        List<String> codes = jdbc.queryForList("SELECT DISTINCT system_code FROM key_versions", String.class);
        java.time.Instant cutoff = java.time.Instant.now().minusSeconds(retentionSeconds);
        int removed = 0;
        for (String code : codes) {
            List<java.util.Map<String, Object>> rows = jdbc.queryForList(
                    "SELECT kid, created_at FROM key_versions WHERE system_code=? AND state='retired' ORDER BY seq DESC",
                    code);
            for (int i = keepPerSystem; i < rows.size(); i++) {
                Object raw = rows.get(i).get("created_at");
                java.time.Instant created = null;
                if (raw instanceof java.sql.Timestamp ts) {
                    created = ts.toInstant();
                } else if (raw instanceof java.time.LocalDateTime ldt) {
                    created = ldt.toInstant(java.time.ZoneOffset.UTC);
                }
                if (created != null && created.isBefore(cutoff)) {
                    jdbc.update("DELETE FROM key_versions WHERE kid=?", rows.get(i).get("kid"));
                    removed++;
                }
            }
        }
        return removed;
    }
    public void saveSystem(Model.SystemRec s) {
        jdbc.update("""
                INSERT INTO systems(code,name,ip_allow,status,mode,note,created_at) VALUES(?,?,?,?,?,?,?)
                ON DUPLICATE KEY UPDATE name=VALUES(name), ip_allow=VALUES(ip_allow), status=VALUES(status),
                  mode=VALUES(mode), note=VALUES(note)
                """, s.code, s.name, writeList(s.ipAllow), s.status, s.mode, s.note, Timestamp.from(s.createdAt));
    }

    public void saveVersion(Model.KeyVersion v) {
        jdbc.update("""
                INSERT INTO key_versions(kid,system_code,seq,alg,public_key,wrapped_priv,state,not_before,decrypt_until,created_at)
                VALUES(?,?,?,?,?,?,?,?,?,?)
                ON DUPLICATE KEY UPDATE public_key=VALUES(public_key), wrapped_priv=VALUES(wrapped_priv), state=VALUES(state),
                  not_before=VALUES(not_before), decrypt_until=VALUES(decrypt_until)
                """, v.kid, v.code, v.seq, v.alg, v.spki, v.wrapped, v.state,
                Timestamp.from(v.notBefore), v.decryptUntil == null ? null : Timestamp.from(v.decryptUntil),
                Timestamp.from(v.createdAt));
    }

    public void saveAudit(Model.Audit a) {
        jdbc.update("INSERT INTO audit_log(ts,actor,action,system_code,kid,ip,result) VALUES(?,?,?,?,?,?,?)",
                Timestamp.from(a.ts), a.actor, a.action, a.system, a.kid, a.ip, a.result);
    }

    public List<Model.Audit> loadAudit(int limit) {
        return jdbc.query("SELECT ts,actor,action,system_code,kid,ip,result FROM audit_log ORDER BY ts DESC LIMIT ?",
                (rs, i) -> {
                    Model.Audit a = new Model.Audit();
                    a.ts = toInstant(rs.getTimestamp("ts"));
                    a.actor = rs.getString("actor");
                    a.action = rs.getString("action");
                    a.system = rs.getString("system_code");
                    a.kid = rs.getString("kid");
                    a.ip = rs.getString("ip");
                    a.result = rs.getString("result");
                    return a;
                }, limit);
    }

    private static Instant toInstant(Timestamp ts) {
        return ts == null ? null : ts.toInstant();
    }

    private List<String> parseList(String s) {
        try {
            return json.readValue(s, new TypeReference<List<String>>() {
            });
        } catch (Exception e) {
            return new ArrayList<>();
        }
    }

    private String writeList(List<String> list) {
        try {
            return json.writeValueAsString(list == null ? List.of() : list);
        } catch (Exception e) {
            return "[]";
        }
    }

    /** 以資料庫為互斥：同一時間只有一個實例能變更金鑰狀態。 */
    public boolean tryLease(String name, String owner, int seconds) {
        jdbc.update("INSERT IGNORE INTO service_locks(name,owner,expires_at) VALUES(?,?,DATE_ADD(NOW(6), INTERVAL ? SECOND))",
                name, owner, seconds);
        jdbc.update("UPDATE service_locks SET owner=?, expires_at=DATE_ADD(NOW(6), INTERVAL ? SECOND) " +
                "WHERE name=? AND (owner=? OR expires_at < NOW(6))", owner, seconds, name, owner);
        String got = jdbc.queryForObject("SELECT owner FROM service_locks WHERE name=?", String.class, name);
        return owner.equals(got);
    }
    public Map<String, Object> ping() {
        jdbc.queryForObject("SELECT 1", Integer.class);
        return Map.of("ok", true);
    }
}
