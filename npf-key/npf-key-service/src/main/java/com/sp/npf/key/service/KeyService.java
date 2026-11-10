package com.sp.npf.key.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

import com.sp.npf.key.config.ClientRegistry;
import com.sp.npf.key.config.NpfProperties;
import com.sp.npf.key.crypto.KmsCipher;
import com.sp.npf.key.store.KeyRepository;
import com.sp.npf.key.store.KeyRepository.KeyRow;

@Service
public class KeyService {

    private static final Logger log = LoggerFactory.getLogger(KeyService.class);
    private static final SecureRandom RANDOM = new SecureRandom();

    public static final String FETCH = "FETCH";
    public static final String FETCH_NOCHANGE = "FETCH_NOCHANGE";
    public static final String ROTATE = "ROTATE";
    public static final String FORCE_ROTATE = "FORCE_ROTATE";
    public static final String ROTATE_SKIPPED = "ROTATE_SKIPPED";
    public static final String CREATE = "CREATE";
    public static final String IMPORT = "IMPORT";
    public static final String DENIED = "DENIED";

    private final NpfProperties props;
    private final KeyRepository repo;
    private final ClientRegistry registry;
    private final KmsCipher kms;
    private final TransactionTemplate tx;
    private final JdbcTemplate jdbc;

    public KeyService(NpfProperties props, KeyRepository repo, ClientRegistry registry,
                      KmsCipher kms, TransactionTemplate tx, JdbcTemplate jdbc) {
        this.props = props;
        this.repo = repo;
        this.registry = registry;
        this.kms = kms;
        this.tx = tx;
        this.jdbc = jdbc;
    }

    /** 啟動時依設定對帳：名單有、DB 沒有的 HMAC 鑰就建立。 */
    @EventListener(ApplicationReadyEvent.class)
    public void onReady() {
        try {
            reconcile();
        } catch (Exception e) {
            log.error("[key-service] 啟動對帳失敗", e);
        }
    }

    public synchronized void reconcile() {
        for (NpfProperties.Hmac h : props.getKeys().getHmac()) {
            if (h.getName() == null || h.getName().isEmpty()) {
                continue;
            }
            if (repo.findCurrent(h.getName()).isPresent()) {
                continue;
            }
            try {
                tx.execute(status -> {
                    if (repo.findCurrentForUpdate(h.getName()).isPresent()) {
                        return null;
                    }
                    createVersion(h.getName(), "HMAC", randomKey(), h.getRemark(), CREATE, "system", null);
                    return null;
                });
                log.info("[key-service] created key {}", h.getName());
            } catch (Exception e) {
                log.error("[key-service] create key failed name={}", h.getName(), e);
            }
        }
    }

    public KeyRepository.KeyRow rotate(String keyName, boolean dropPrevious, String reason, String sourceIp) {
        return rotateInternal(keyName, dropPrevious, reason, sourceIp, false);
    }

    private KeyRow rotateInternal(String keyName, boolean dropPrevious, String reason, String sourceIp, boolean scheduled) {
        return tx.execute(status -> {
            KeyRow current = repo.findCurrentForUpdate(keyName)
                    .orElseThrow(() -> new ApiException(404, "key not found: " + keyName));
            Instant now = Instant.now();
            if (!dropPrevious && current.rotatedAt != null
                    && current.rotatedAt.isAfter(now.minus(Duration.ofHours(props.getRotate().getMinIntervalHours())))) {
                throw new ApiException(409, "rotated too recently");
            }
            Optional<KeyRow> previous = repo.findPrevious(keyName);
            KeyRow created = createVersion(keyName, "HMAC", randomKey(), current.remark,
                    scheduled ? ROTATE : FORCE_ROTATE, sourceIp, now);
            repo.markPrevious(current.id, now);
            if (dropPrevious && previous.isPresent()) {
                repo.markRetired(previous.get().id);
            }
            log.info("[key-service] rotated key={} version={}", keyName, created.version);
            return created;
        });
    }

    public KeyRow importPartner(String keyName, byte[] value, String remark, String reason, String sourceIp) {
        return tx.execute(status -> {
            Optional<KeyRow> current = repo.findCurrentForUpdate(keyName);
            Optional<KeyRow> previous = repo.findPrevious(keyName);
            int version = repo.maxVersion(keyName) + 1;
            KeyRow created = buildRow(keyName, "PARTNER", version, value, remark, "PARTNER");
            repo.insert(created);
            if (current.isPresent()) {
                repo.markPrevious(current.get().id, Instant.now());
            }
            if (previous.isPresent()) {
                repo.markRetired(previous.get().id);
            }
            repo.audit(IMPORT, "admin", keyName, version, sourceIp, reason);
            return created;
        });
    }

    public FetchResult fetch(String clientId, String remoteIp, String keyName, String etag) {
        NpfProperties.Client client = registry.resolve(remoteIp);
        if (client == null || (clientId != null && !clientId.isEmpty() && !clientId.equals(client.getId()))) {
            log.warn("[key-service] denied ip={} clientId={} resolved={}", remoteIp, clientId, client == null ? null : client.getId());
            repo.audit(DENIED, clientId, keyName, null, remoteIp, "client/ip mismatch");
            throw new ApiException(403, "forbidden");
        }
        List<String> names;
        if (keyName == null || keyName.isEmpty()) {
            names = new ArrayList<>(client.getAllowedKeys());
        } else {
            if (!client.getAllowedKeys().contains(keyName)) {
                repo.audit(DENIED, clientId, keyName, null, remoteIp, "key not allowed");
                throw new ApiException(403, "forbidden");
            }
            names = Collections.singletonList(keyName);
        }

        Map<String, Object> keys = new LinkedHashMap<>();
        for (String name : names) {
            Optional<KeyRow> current = repo.findCurrent(name);
            if (!current.isPresent()) {
                continue;
            }
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("current", ref(current.get()));
            Optional<KeyRow> previous = repo.findPrevious(name);
            entry.put("previous", previous.map(this::ref).orElse(null));
            keys.put(name, entry);
        }

        String newEtag = etag(keys);
        String incoming = normalizeEtag(etag);
        if (incoming != null && incoming.equals(newEtag)) {
            repo.audit(FETCH_NOCHANGE, clientId, keyName, null, remoteIp, "");
            return FetchResult.notModified(newEtag);
        }
        repo.audit(FETCH, clientId, keyName, null, remoteIp, "");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("etag", newEtag);
        body.put("refresh", props.getRefreshSeconds());
        body.put("keys", keys);
        return FetchResult.ok(newEtag, body);
    }

    /** 稽核保留 180 天，每天 03:30 清理。 */
    @Scheduled(cron = "${npf.audit-prune-cron:0 30 3 * * *}", zone = "${npf.rotate.zone:Asia/Shanghai}")
    public void pruneAudit() {
        int days = props.getAuditRetentionDays();
        int deleted = jdbc.update("DELETE FROM KEY_AUDIT_LOG WHERE OCCURRED_AT < ?",
                java.sql.Timestamp.from(Instant.now().minus(Duration.ofDays(days))));
        if (deleted > 0) {
            log.info("[key-service] pruned {} audit rows older than {} days", deleted, days);
        }
    }

    @Scheduled(cron = "${npf.rotate.cron:0 0 10 * * *}", zone = "${npf.rotate.zone:Asia/Shanghai}")
    public void scheduledRotate() {
        for (NpfProperties.Hmac h : props.getKeys().getHmac()) {
            String name = h.getName();
            if (name == null || name.isEmpty()) {
                continue;
            }
            try {
                KeyRow current = repo.findCurrent(name).orElse(null);
                if (current == null) {
                    continue;
                }
                if (current.rotatedAt != null
                        && current.rotatedAt.isAfter(Instant.now().minus(Duration.ofHours(props.getRotate().getMinIntervalHours())))) {
                    repo.audit(ROTATE_SKIPPED, "scheduler", name, current.version, "127.0.0.1", "min interval");
                    continue;
                }
                rotateInternal(name, false, "scheduled", "127.0.0.1", true);
            } catch (Exception e) {
                log.error("[key-service] scheduled rotate failed name={}", name, e);
            }
        }
    }

    public Map<String, Object> health() {
        Map<String, Object> m = new LinkedHashMap<>();
        boolean db = repo.ping();
        m.put("status", db ? "UP" : "DOWN");
        m.put("db", db ? "UP" : "DOWN");
        m.put("kms", kms.describe());
        return m;
    }

    private KeyRow createVersion(String keyName, String type, byte[] plain, String remark, String action,
                                String sourceIp, Instant rotatedAt) {
        int version = repo.maxVersion(keyName) + 1;
        KeyRow row = buildRow(keyName, type, version, plain, remark, "KMS");
        row.rotatedAt = rotatedAt;
        repo.insert(row);
        repo.audit(action, "system", keyName, version, sourceIp, "");
        return row;
    }

    private KeyRow buildRow(String keyName, String type, int version, byte[] plain, String remark, String kmsTag) {
        Instant now = Instant.now();
        KeyRow row = new KeyRow();
        row.keyName = keyName;
        row.keyType = type;
        row.version = version;
        row.keyId = hex(8);
        row.status = KeyRepository.CURRENT;
        row.cipherText = kms.encrypt(keyName, plain);
        row.kmsKeyId = kmsTag;
        row.createdAt = now;
        row.updatedAt = now;
        row.rotatedAt = null;
        row.remark = remark == null ? "" : remark;
        row.rotateEnabled = true;
        return row;
    }

    private Map<String, Object> ref(KeyRow row) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", row.keyId);
        m.put("value", Base64.getEncoder().encodeToString(kms.decrypt(row.keyName, row.cipherText)));
        return m;
    }

    private static String normalizeEtag(String raw) {
        if (raw == null) {
            return null;
        }
        String s = raw.trim();
        if (s.startsWith("W/")) {
            s = s.substring(2);
        }
        if (s.length() >= 2 && s.startsWith("\"") && s.endsWith("\"")) {
            s = s.substring(1, s.length() - 1);
        }
        return s;
    }

    private String etag(Map<String, Object> keys) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, Object> e : keys.entrySet()) {
            @SuppressWarnings("unchecked")
            Map<String, Object> entry = (Map<String, Object>) e.getValue();
            @SuppressWarnings("unchecked")
            Map<String, Object> current = (Map<String, Object>) entry.get("current");
            @SuppressWarnings("unchecked")
            Map<String, Object> previous = (Map<String, Object>) entry.get("previous");
            sb.append(e.getKey()).append(':').append(current.get("id"));
            if (previous != null) {
                sb.append(':').append(previous.get("id"));
            }
            sb.append(';');
        }
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(sb.toString().getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (int i = 0; i < 8; i++) {
                hex.append(String.format("%02x", d[i]));
            }
            return hex.toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] randomKey() {
        byte[] b = new byte[32];
        RANDOM.nextBytes(b);
        return b;
    }

    private static String hex(int bytes) {
        byte[] b = new byte[bytes];
        RANDOM.nextBytes(b);
        StringBuilder sb = new StringBuilder();
        for (byte x : b) {
            sb.append(String.format("%02x", x));
        }
        return sb.toString();
    }

    public static class FetchResult {
        public final boolean notModified;
        public final String etag;
        public final Map<String, Object> body;

        private FetchResult(boolean notModified, String etag, Map<String, Object> body) {
            this.notModified = notModified;
            this.etag = etag;
            this.body = body;
        }

        static FetchResult notModified(String etag) {
            return new FetchResult(true, etag, null);
        }

        static FetchResult ok(String etag, Map<String, Object> body) {
            return new FetchResult(false, etag, body);
        }
    }
}
