package com.example.keyserver;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;

@Service
public class KeyService {

    private static final Logger log = LoggerFactory.getLogger(KeyService.class);
    private static final Pattern CODE = Pattern.compile("^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$");

    public static final String PENDING = "pending";
    public static final String ACTIVE = "active";
    public static final String DECRYPT_ONLY = "decrypt_only";
    public static final String RETIRED = "retired";

    private final AppConfig cfg;
    private final Store store;
    private final Map<String, Model.SystemRec> systems = new ConcurrentHashMap<>();
    private final Map<String, List<Model.KeyVersion>> versions = new ConcurrentHashMap<>();
    private final byte[] kek;
    private final AtomicLong syncTotal = new AtomicLong();
    private final AtomicLong deniedTotal = new AtomicLong();
    private final AtomicLong privateIssued = new AtomicLong();
    private final AtomicLong privateDenied = new AtomicLong();
    private final AtomicLong rotations = new AtomicLong();

    public KeyService(AppConfig cfg, Store store) {
        this.cfg = cfg;
        this.store = store;
        this.kek = Crypto.hexToBytes(cfg.kekHex);
        if (kek.length != 32) {
            throw new IllegalStateException("KEY_KEK 必須是 64 位十六進位（32 bytes）");
        }
    }

    @PostConstruct
    public synchronized void init() {
        store.ensureSchema();
        for (Model.SystemRec s : store.loadSystems()) {
            systems.put(s.code, s);
        }
        for (Model.KeyVersion v : store.loadVersions()) {
            versions.computeIfAbsent(v.code, k -> new ArrayList<>()).add(v);
        }
        log.info("載入 {} 個系統、{} 個版本", systems.size(), versions.values().stream().mapToInt(List::size).sum());
    }

    private final String owner = ownerName();

    private static String ownerName() {
        try {
            return java.net.InetAddress.getLocalHost().getHostName() + "-" + ProcessHandle.current().pid();
        } catch (Exception e) {
            return "instance-" + ProcessHandle.current().pid();
        }
    }
    private volatile long lastReload = 0;

    /** 從資料庫重載，讓多實例看到彼此的變更。 */
    public synchronized void reload() {
        systems.clear();
        versions.clear();
        for (Model.SystemRec s : store.loadSystems()) {
            systems.put(s.code, s);
        }
        for (Model.KeyVersion v : store.loadVersions()) {
            versions.computeIfAbsent(v.code, k -> new ArrayList<>()).add(v);
        }
        lastReload = System.currentTimeMillis();
    }

    /** 讀取前最多每秒重載一次。 */
    private void maybeReload() {
        if (System.currentTimeMillis() - lastReload >= 1000) {
            reload();
        }
    }

    /** 變更前先拿租約並重載，避免多實例互相覆蓋。 */
    private void beginMutation() {
        if (!store.tryLease("rotation", owner, 10)) {
            throw new ApiException(409, "busy", "另一個實例正在變更，請稍後重試");
        }
        reload();
    }
    // ---------- 查詢 ----------

    public synchronized List<Model.SystemRec> listSystems() {
        maybeReload();
        return systems.values().stream().sorted(Comparator.comparing(s -> s.code)).toList();
    }

    public synchronized Model.SystemRec system(String code) {
        Model.SystemRec s = systems.get(code);
        if (s == null) {
            throw new ApiException(404, "unknown_system", "系統未登記：" + code);
        }
        return s;
    }

    // ---------- 登記與停用 ----------

    public synchronized Model.SystemRec register(String code, String name, List<String> ipAllow, String note) {
        beginMutation();
        if (code == null || !CODE.matcher(code).matches()) {
            throw new ApiException(400, "invalid_code", "系統代碼只能含英數、_、-，且以英數開頭");
        }
        if (systems.containsKey(code)) {
            throw new ApiException(409, "exists", "系統已存在：" + code);
        }
        Model.SystemRec s = new Model.SystemRec();
        s.code = code;
        s.name = name == null || name.isBlank() ? code : name;
        s.ipAllow = ipAllow == null ? new ArrayList<>() : new ArrayList<>(ipAllow);
        s.note = note == null ? "" : note;
        s.createdAt = Instant.now();
        systems.put(code, s);
        store.saveSystem(s);
        createVersion(code, s.createdAt, ACTIVE);
        audit("admin", "system.register", code, "", "", "ok");
        return s;
    }

    public synchronized Model.SystemRec setStatus(String code, String status, String actor) {
        beginMutation();
        Model.SystemRec s = system(code);
        if (!status.equals("enabled") && !status.equals("disabled")) {
            throw new ApiException(400, "invalid_status", "狀態只能是 enabled 或 disabled");
        }
        s.status = status;
        store.saveSystem(s);
        if (status.equals("disabled")) {
            // 停用即作廢現行金鑰
            for (Model.KeyVersion v : versions.getOrDefault(code, List.of())) {
                if (ACTIVE.equals(v.state)) {
                    v.state = RETIRED;
                    v.wrapped = null;
                    store.saveVersion(v);
                }
            }
        } else if (versions.getOrDefault(code, List.of()).stream().noneMatch(v -> ACTIVE.equals(v.state))) {
            createVersion(code, Instant.now(), ACTIVE);
        }
        audit(actor, "system." + status, code, "", "", "ok");
        return s;
    }

    // ---------- 輪替 ----------

    /** 立即輪替：舊版進緩衝期，新版本立刻生效。 */
    public synchronized Model.KeyVersion rotate(String code, String actor, String ip) {
        beginMutation();
        Model.SystemRec s = system(code);
        if (!"enabled".equals(s.status)) {
            throw new ApiException(409, "disabled", "系統已停用");
        }
        Instant now = Instant.now();
        for (Model.KeyVersion v : versions.getOrDefault(code, List.of())) {
            if (ACTIVE.equals(v.state)) {
                v.state = DECRYPT_ONLY;
                v.decryptUntil = now.plusSeconds(cfg.graceSeconds);
                store.saveVersion(v);
            } else if (DECRYPT_ONLY.equals(v.state)) {
                v.state = RETIRED;
                v.wrapped = null;
                store.saveVersion(v);
            }
        }
        Model.KeyVersion nv = createVersion(code, now, ACTIVE);
        store.demoteOthers(code, nv.kid, now.plusSeconds(cfg.graceSeconds));
        reload();
        rotations.incrementAndGet();
        audit(actor, "key.rotate", code, nv.kid, ip, "ok");
        return nv;
    }

    /** 排程輪替：建立 pending，prepublish 後生效。 */
    public synchronized Model.KeyVersion schedule(String code, String actor, String ip) {
        beginMutation();
        Model.SystemRec s = system(code);
        if (!"enabled".equals(s.status)) {
            throw new ApiException(409, "disabled", "系統已停用");
        }
        boolean hasPending = versions.getOrDefault(code, List.of()).stream().anyMatch(v -> PENDING.equals(v.state));
        if (hasPending) {
            throw new ApiException(409, "pending", "已有待生效版本");
        }
        Instant activateAt = Instant.now().plusSeconds(cfg.prepublishSeconds);
        Model.KeyVersion nv = createVersion(code, activateAt, PENDING);
        audit(actor, "key.schedule-rotate", code, nv.kid, ip, "activate_at=" + activateAt);
        return nv;
    }

    public synchronized int autoRotate(Instant now) {
        if (!store.tryLease("rotation", owner, 10)) {
            return 0;
        }
        reload();
        int count = 0;
        for (Model.SystemRec s : systems.values()) {
            if (!"enabled".equals(s.status)) {
                continue;
            }
            List<Model.KeyVersion> list = versions.getOrDefault(s.code, List.of());
            boolean pending = list.stream().anyMatch(v -> PENDING.equals(v.state));
            Model.KeyVersion active = list.stream().filter(v -> ACTIVE.equals(v.state))
                    .max(Comparator.comparing(v -> v.notBefore)).orElse(null);
            if (pending || active == null) {
                continue;
            }
            if (Duration.between(active.notBefore, now).getSeconds() < cfg.rotationSeconds) {
                continue;
            }
            try {
                Model.KeyVersion nv = createVersion(s.code, now.plusSeconds(cfg.prepublishSeconds), PENDING);
                rotations.incrementAndGet();
                audit("scheduler", "key.schedule-rotate", s.code, nv.kid, "", "activate_at=" + nv.notBefore);
                count++;
            } catch (Exception e) {
                log.warn("排程輪替 {} 失敗：{}", s.code, e.getMessage());
            }
        }
        return count;
    }

    /** 推進狀態：pending→active、active→decrypt_only、逾時→retired。 */
    public synchronized void tick(Instant now) {
        for (Map.Entry<String, List<Model.KeyVersion>> e : versions.entrySet()) {
            List<Model.KeyVersion> list = e.getValue();
            boolean changed = false;
            for (Model.KeyVersion v : list) {
                if (PENDING.equals(v.state) && !v.notBefore.isAfter(now)) {
                    for (Model.KeyVersion old : list) {
                        if (old != v && ACTIVE.equals(old.state)) {
                            old.state = DECRYPT_ONLY;
                            old.decryptUntil = now.plusSeconds(cfg.graceSeconds);
                        }
                    }
                    v.state = ACTIVE;
                    changed = true;
                    audit("scheduler", "key.activate", e.getKey(), v.kid, "", "ok");
                }
            }
            for (Model.KeyVersion v : list) {
                if (DECRYPT_ONLY.equals(v.state)) {
                    if (v.decryptUntil != null && !v.decryptUntil.isAfter(now)) {
                        v.state = RETIRED;
                        v.wrapped = null;
                        changed = true;
                    } else if (v.decryptUntil == null) {
                        v.state = RETIRED;
                        v.wrapped = null;
                        changed = true;
                    }
                }
            }
            if (changed) {
                for (Model.KeyVersion v : list) {
                    store.saveVersion(v);
                }
            }
        }
    }

    // ---------- 同步與私鑰 ----------

    public synchronized Map<String, Object> sync(String code, String clientIp) {
        maybeReload();
        syncTotal.incrementAndGet();
        Model.SystemRec s = system(code);
        if (!"enabled".equals(s.status)) {
            deniedTotal.incrementAndGet();
            throw new ApiException(403, "disabled", "系統已停用");
        }
        if (!ipAllowed(s, clientIp)) {
            deniedTotal.incrementAndGet();
            throw new ApiException(403, "ip_denied", "來源 IP 不符");
        }
        Instant now = Instant.now();
        tick(now);

        List<Map<String, Object>> decrypt = new ArrayList<>();
        for (Model.KeyVersion v : versions.getOrDefault(code, List.of())) {
            if (ACTIVE.equals(v.state) || DECRYPT_ONLY.equals(v.state)) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("kid", v.kid);
                m.put("alg", v.alg);
                m.put("not_before", v.notBefore.toString());
                if (v.decryptUntil != null) {
                    m.put("decrypt_until", v.decryptUntil.toString());
                }
                decrypt.add(m);
            }
        }

        Map<String, Object> peers = new LinkedHashMap<>();
        Map<String, Object> next = new LinkedHashMap<>();
        for (Model.SystemRec other : systems.values()) {
            if (other.code.equals(code) || !"enabled".equals(other.status)) {
                continue;
            }
            for (Model.KeyVersion v : versions.getOrDefault(other.code, List.of())) {
                if (ACTIVE.equals(v.state)) {
                    peers.put(other.code, ref(v));
                } else if (PENDING.equals(v.state)) {
                    next.put(other.code, ref(v));
                }
            }
        }

        Map<String, Object> self = new LinkedHashMap<>();
        self.put("system_code", code);
        self.put("encryption", Map.of("mode", s.mode, "policy_id", "p-" + code));
        self.put("decrypt_versions", decrypt);

        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("server_time", now.toString());
        resp.put("self", self);
        resp.put("peers", peers);
        if (!next.isEmpty()) {
            resp.put("next", next);
        }
        return resp;
    }

    public synchronized Map<String, Object> privateKey(String code, String kid, String clientIp) {
        maybeReload();
        Model.SystemRec s = system(code);
        if (!"enabled".equals(s.status)) {
            privateDenied.incrementAndGet();
            throw new ApiException(403, "disabled", "系統已停用");
        }
        if (!ipAllowed(s, clientIp)) {
            privateDenied.incrementAndGet();
            throw new ApiException(403, "ip_denied", "來源 IP 不符");
        }
        Instant now = Instant.now();
        tick(now);
        Model.KeyVersion found = null;
        for (Model.KeyVersion v : versions.getOrDefault(code, List.of())) {
            if (v.kid.equals(kid)) {
                found = v;
                break;
            }
        }
        if (found == null) {
            privateDenied.incrementAndGet();
            throw new ApiException(404, "unknown_kid", "kid 不存在：" + kid);
        }
        if (!found.code.equals(code)) {
            privateDenied.incrementAndGet();
            throw new ApiException(403, "forbidden", "kid 不屬於此系統");
        }
        boolean okState = ACTIVE.equals(found.state) || PENDING.equals(found.state)
                || (DECRYPT_ONLY.equals(found.state) && found.decryptUntil != null && !found.decryptUntil.isBefore(now));
        if (!okState || found.wrapped == null) {
            privateDenied.incrementAndGet();
            throw new ApiException(403, "retired", "版本已退役：" + kid);
        }
        try {
            PrivateKey priv = Crypto.privateFromScalar(Crypto.unwrap(kek, found.wrapped));
            privateIssued.incrementAndGet();
            audit(code, "key.private-key", code, kid, clientIp, "ok");
            Map<String, Object> resp = new LinkedHashMap<>();
            resp.put("kid", found.kid);
            resp.put("alg", found.alg);
            resp.put("private_key_b64", Base64.getEncoder().encodeToString(Crypto.pkcs8(priv)));
            return resp;
        } catch (Exception e) {
            privateDenied.incrementAndGet();
            throw new ApiException(500, "unwrap_failed", "私鑰解封失敗");
        }
    }

    public synchronized String activeKid(String code) {
        return versions.getOrDefault(code, List.of()).stream()
                .filter(v -> ACTIVE.equals(v.state))
                .map(v -> v.kid)
                .findFirst().orElse("");
    }

    public synchronized List<Model.KeyVersion> versionsOf(String code) {
        maybeReload();
        return List.copyOf(versions.getOrDefault(code, List.of()));
    }
    /** 清理退役版本並重載，回傳刪除數。 */
    public synchronized int pruneNow() {
        int n = store.pruneRetired(cfg.retentionSeconds, cfg.retentionKeep);
        if (n > 0) {
            reload();
        }
        return n;
    }
    // ---------- 內部 ----------

    private Map<String, Object> ref(Model.KeyVersion v) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("kid", v.kid);
        m.put("alg", v.alg);
        m.put("public_key", Base64.getEncoder().encodeToString(v.spki));
        m.put("not_before", v.notBefore.toString());
        return m;
    }

    private Model.KeyVersion createVersion(String code, Instant notBefore, String state) {
        try {
            KeyPair kp = Crypto.generate();
            byte[] scalar = Crypto.scalar(kp.getPrivate());
            byte[] wrapped = Crypto.wrap(kek, Crypto.pkcs8(kp.getPrivate()));
            List<Model.KeyVersion> list = versions.computeIfAbsent(code, k -> new ArrayList<>());
            int seq;
            try {
                seq = store.nextSeq(code);
            } catch (RuntimeException ex) {
                // 系統剛登記、尚未落庫：先用記憶體序號
                seq = list.stream().mapToInt(v -> v.seq).max().orElse(0) + 1;
                Model.SystemRec s = systems.get(code);
                if (s != null) {
                    s.nextSeq = seq + 1;
                }
            }
            Model.KeyVersion v = new Model.KeyVersion();
            v.kid = code + ":" + seq;
            v.code = code;
            v.seq = seq;
            v.spki = Crypto.spki(kp.getPublic());
            v.wrapped = wrapped;
            v.state = state;
            v.notBefore = notBefore;
            v.createdAt = Instant.now();
            list.add(v);
            store.saveVersion(v);
            return v;
        } catch (Exception e) {
            throw new ApiException(500, "keygen_failed", "金鑰產生失敗：" + e.getMessage());
        }
    }

    public boolean ipAllowed(Model.SystemRec s, String ip) {
        if (s.ipAllow == null || s.ipAllow.isEmpty()) {
            return true;
        }
        for (String rule : s.ipAllow) {
            if (IpRules.matches(rule, ip)) {
                return true;
            }
        }
        return false;
    }

    private void audit(String actor, String action, String system, String kid, String ip, String result) {
        Model.Audit a = new Model.Audit();
        a.ts = Instant.now();
        a.actor = actor;
        a.action = action;
        a.system = system;
        a.kid = kid;
        a.ip = ip == null ? "" : ip;
        a.result = result;
        try {
            store.saveAudit(a);
        } catch (Exception e) {
            log.warn("寫入稽核失敗：{}", e.getMessage());
        }
    }

    public List<Model.Audit> auditList(int limit) {
        return store.loadAudit(Math.min(Math.max(limit, 1), 500));
    }

    public String metrics() {
        return """
                # TYPE key_sync_total counter
                key_sync_total %d
                # TYPE key_sync_denied_total counter
                key_sync_denied_total %d
                # TYPE key_private_key_issued_total counter
                key_private_key_issued_total %d
                # TYPE key_private_key_denied_total counter
                key_private_key_denied_total %d
                # TYPE key_rotations_total counter
                key_rotations_total %d
                # TYPE key_systems_enabled gauge
                key_systems_enabled %d
                """.formatted(syncTotal.get(), deniedTotal.get(), privateIssued.get(), privateDenied.get(),
                rotations.get(), systems.values().stream().filter(s -> "enabled".equals(s.status)).count());
    }

    public byte[] kekBytes() {
        return kek;
    }

    public String storeInfo() {
        return store.info();
    }

    static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }
}
