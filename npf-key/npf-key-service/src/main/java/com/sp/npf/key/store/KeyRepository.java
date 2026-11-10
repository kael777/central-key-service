package com.sp.npf.key.store;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

@Repository
public class KeyRepository {

    public static final String CURRENT = "CURRENT";
    public static final String PREVIOUS = "PREVIOUS";
    public static final String RETIRED = "RETIRED";

    private final JdbcTemplate jdbc;

    public KeyRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    private static final RowMapper<KeyRow> MAPPER = new RowMapper<KeyRow>() {
        @Override
        public KeyRow mapRow(ResultSet rs, int i) throws SQLException {
            KeyRow k = new KeyRow();
            k.id = rs.getLong("ID");
            k.keyName = rs.getString("KEY_NAME");
            k.keyType = rs.getString("KEY_TYPE");
            k.version = rs.getInt("VERSION");
            k.keyId = rs.getString("KEY_ID");
            k.status = rs.getString("STATUS");
            k.cipherText = rs.getBytes("CIPHER_TEXT");
            k.kmsKeyId = rs.getString("KMS_KEY_ID");
            k.createdAt = toInstant(rs.getTimestamp("CREATED_AT"));
            k.updatedAt = toInstant(rs.getTimestamp("UPDATED_AT"));
            k.rotatedAt = toInstant(rs.getTimestamp("ROTATED_AT"));
            k.remark = rs.getString("REMARK");
            k.rotateEnabled = rs.getInt("ROTATE_ENABLED") == 1;
            return k;
        }
    };

    public Optional<KeyRow> findCurrentForUpdate(String keyName) {
        List<KeyRow> rows = jdbc.query(
                "SELECT * FROM KEY_SECRET WHERE KEY_NAME = ? AND STATUS = 'CURRENT' FOR UPDATE",
                MAPPER, keyName);
        return rows.isEmpty() ? Optional.<KeyRow>empty() : Optional.of(rows.get(0));
    }

    public Optional<KeyRow> findCurrent(String keyName) {
        List<KeyRow> rows = jdbc.query(
                "SELECT * FROM KEY_SECRET WHERE KEY_NAME = ? AND STATUS = 'CURRENT'", MAPPER, keyName);
        return rows.isEmpty() ? Optional.<KeyRow>empty() : Optional.of(rows.get(0));
    }

    public Optional<KeyRow> findPrevious(String keyName) {
        List<KeyRow> rows = jdbc.query(
                "SELECT * FROM KEY_SECRET WHERE KEY_NAME = ? AND STATUS = 'PREVIOUS'", MAPPER, keyName);
        return rows.isEmpty() ? Optional.<KeyRow>empty() : Optional.of(rows.get(0));
    }

    public List<KeyRow> findActive(String keyName) {
        return jdbc.query(
                "SELECT * FROM KEY_SECRET WHERE KEY_NAME = ? AND STATUS IN ('CURRENT','PREVIOUS') ORDER BY VERSION DESC",
                MAPPER, keyName);
    }

    public int maxVersion(String keyName) {
        Integer v = jdbc.queryForObject(
                "SELECT COALESCE(MAX(VERSION),0) FROM KEY_SECRET WHERE KEY_NAME = ?", Integer.class, keyName);
        return v == null ? 0 : v;
    }

    public void insert(KeyRow k) {
        jdbc.update("INSERT INTO KEY_SECRET (KEY_NAME, KEY_TYPE, VERSION, KEY_ID, STATUS, CIPHER_TEXT, "
                        + "KMS_KEY_ID, CREATED_AT, UPDATED_AT, ROTATED_AT, REMARK, ROTATE_ENABLED) "
                        + "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                k.keyName, k.keyType, k.version, k.keyId, k.status, k.cipherText, k.kmsKeyId,
                Timestamp.from(k.createdAt), Timestamp.from(k.updatedAt),
                k.rotatedAt == null ? null : Timestamp.from(k.rotatedAt),
                k.remark, k.rotateEnabled ? 1 : 0);
    }

    public void markRetired(long id) {
        jdbc.update("UPDATE KEY_SECRET SET STATUS = 'RETIRED', UPDATED_AT = ? WHERE ID = ?",
                Timestamp.from(Instant.now()), id);
    }

    public void markPrevious(long id, Instant rotatedAt) {
        jdbc.update("UPDATE KEY_SECRET SET STATUS = 'PREVIOUS', ROTATED_AT = ?, UPDATED_AT = ? WHERE ID = ?",
                Timestamp.from(rotatedAt), Timestamp.from(rotatedAt), id);
    }

    public void audit(String action, String clientId, String keyName, Integer version, String sourceIp, String reason) {
        jdbc.update("INSERT INTO KEY_AUDIT_LOG (OCCURRED_AT, ACTION, CLIENT_ID, KEY_NAME, VERSION, SOURCE_IP, REASON) "
                        + "VALUES (?,?,?,?,?,?,?)",
                Timestamp.from(Instant.now()), action, clientId, keyName, version, sourceIp, reason);
    }

    public boolean ping() {
        try {
            jdbc.queryForObject("SELECT 1", Integer.class);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public List<KeyRow> listByName(String keyName) {
        return jdbc.query("SELECT * FROM KEY_SECRET WHERE KEY_NAME = ? ORDER BY VERSION DESC", MAPPER, keyName);
    }

    public List<KeyRow> listAllActive() {
        return jdbc.query("SELECT * FROM KEY_SECRET WHERE STATUS <> 'RETIRED' ORDER BY KEY_NAME, VERSION DESC", MAPPER);
    }

    public List<String> listKeyNames() {
        return jdbc.queryForList("SELECT DISTINCT KEY_NAME FROM KEY_SECRET", String.class);
    }

    private static Instant toInstant(Timestamp ts) {
        return ts == null ? null : ts.toInstant();
    }

    public static class KeyRow {
        public long id;
        public String keyName;
        public String keyType;
        public int version;
        public String keyId;
        public String status;
        public byte[] cipherText;
        public String kmsKeyId;
        public Instant createdAt;
        public Instant updatedAt;
        public Instant rotatedAt;
        public String remark;
        public boolean rotateEnabled;
    }

    public List<KeyRow> emptyList() {
        return Collections.emptyList();
    }
}
