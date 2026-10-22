package keysdk;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/**
 * 網路層：輪詢 /sync、快照快取、私鑰取得、降級判斷。
 *
 * <p>業務系統只需要這一層：
 * <pre>{@code
 * KeyClient client = new KeyClient(KeyClient.config()
 *     .baseUrl("https://key.internal")
 *     .systemCode("SYS-A")
 *     .cert("/etc/key-sdk/client.crt", "/etc/key-sdk/client.key")
 *     .ca("/etc/key-sdk/ca.crt")
 *     .build());
 *
 * String token = client.encrypt("SYS-B", "urlparam", params);
 * byte[] plain = client.decrypt(token, "urlparam");
 * }</pre>
 */
public final class KeyClient implements AutoCloseable {

    public static final Duration MAX_STALENESS = Duration.ofSeconds(60);
    private static final String USER_AGENT = "key-sdk-java/1.0.0";

    /** 對端系統目前的有效版本。 */
    public static final class Peer {
        public final String kid;
        public final byte[] spki;

        Peer(String kid, byte[] spki) {
            this.kid = kid;
            this.spki = spki;
        }
    }

    /** 一次 /sync 的原子快照。 */
    public static final class Snapshot {
        public final String mode;
        public final Map<String, Peer> peers;
        public final Set<String> decryptKids;
        public final long fetchedAt;

        Snapshot(String mode, Map<String, Peer> peers, Set<String> decryptKids, long fetchedAt) {
            this.mode = mode;
            this.peers = peers;
            this.decryptKids = decryptKids;
            this.fetchedAt = fetchedAt;
        }
    }

    /** 設定。 */
    public static final class Config {
        String baseUrl;
        String systemCode;
        String certPath;
        String keyPath;
        String caPath;

        public Config baseUrl(String v) {
            this.baseUrl = v;
            return this;
        }

        public Config systemCode(String v) {
            this.systemCode = v;
            return this;
        }

        public Config cert(String certPath, String keyPath) {
            this.certPath = certPath;
            this.keyPath = keyPath;
            return this;
        }

        public Config ca(String caPath) {
            this.caPath = caPath;
            return this;
        }

        public KeyClient build() throws Exception {
            return new KeyClient(this);
        }
    }

    public static Config config() {
        return new Config();
    }

    private final Config cfg;
    private final HttpClient http;
    private final Map<String, PrivateKey> privateKeys = new ConcurrentHashMap<>();
    private volatile Snapshot snapshot;
    private volatile String etag;

    private KeyClient(Config cfg) throws Exception {
        if (cfg.baseUrl == null || cfg.systemCode == null) {
            throw new IllegalArgumentException("baseUrl 與 systemCode 必填");
        }
        this.cfg = cfg;
        this.http = HttpClient.newBuilder()
                .sslContext(buildSslContext(cfg))
                .connectTimeout(Duration.ofSeconds(5))
                .build();
    }

    private static SSLContext buildSslContext(Config cfg) throws Exception {
        if (cfg.certPath == null || cfg.keyPath == null) {
            throw new IllegalArgumentException("需要用戶端憑證");
        }
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        X509Certificate cert;
        try (var in = Files.newInputStream(Path.of(cfg.certPath))) {
            cert = (X509Certificate) cf.generateCertificate(in);
        }
        byte[] keyDer = KeyCrypto.pemToDer(Files.readString(Path.of(cfg.keyPath)));
        PrivateKey key = KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(keyDer));

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("client", key, new char[0], new java.security.cert.Certificate[]{cert});
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, new char[0]);

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        if (cfg.caPath != null) {
            KeyStore ts = KeyStore.getInstance("PKCS12");
            ts.load(null, null);
            try (var in = Files.newInputStream(Path.of(cfg.caPath))) {
                int i = 0;
                for (var c : cf.generateCertificates(in)) {
                    ts.setCertificateEntry("ca-" + i++, c);
                }
            }
            tmf.init(ts);
        } else {
            // 未指定 CA 時使用 JVM 預設信任庫（公網部署用公開 CA）
            tmf.init((KeyStore) null);
        }

        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return ctx;
    }

    /** 取得最新快照；304 時只更新時間戳。 */
    public Snapshot refresh() throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(cfg.baseUrl + "/api/v1/sync"))
                .header("Accept", "application/json")
                .header("User-Agent", USER_AGENT)
                .timeout(Duration.ofSeconds(10))
                .GET();
        String current = etag;
        if (current != null) {
            b.header("If-None-Match", current);
        }
        HttpResponse<String> res = http.send(b.build(), HttpResponse.BodyHandlers.ofString());

        if (res.statusCode() == 304) {
            Snapshot s = snapshot;
            if (s != null) {
                snapshot = new Snapshot(s.mode, s.peers, s.decryptKids, System.nanoTime());
            }
            return snapshot;
        }
        if (res.statusCode() == 401 || res.statusCode() == 403) {
            throw new KeyError(KeyError.UNAUTHORIZED, "未登記、已停用或憑證無效");
        }
        if (res.statusCode() != 200) {
            throw new KeyError(KeyError.UNAVAILABLE, "中央回應 " + res.statusCode());
        }
        etag = res.headers().firstValue("etag").orElse(null);

        Map<String, Object> doc = Json.obj(Json.parse(res.body()));
        Map<String, Object> self = Json.obj(doc.get("self"));
        Map<String, Object> enc = self.get("encryption") == null ? Map.of() : Json.obj(self.get("encryption"));
        String mode = enc.get("mode") == null ? "required" : Json.str(enc.get("mode"));

        Map<String, Peer> peers = new HashMap<>();
        if (doc.get("peers") != null) {
            for (var e : Json.obj(doc.get("peers")).entrySet()) {
                Map<String, Object> p = Json.obj(e.getValue());
                peers.put(e.getKey(), new Peer(
                        Json.str(p.get("kid")),
                        Base64.getDecoder().decode(Json.str(p.get("public_key")))));
            }
        }
        Set<String> kids = ConcurrentHashMap.newKeySet();
        if (self.get("decrypt_versions") != null) {
            for (Object o : Json.list(self.get("decrypt_versions"))) {
                kids.add(Json.str(Json.obj(o).get("kid")));
            }
        }
        snapshot = new Snapshot(mode, peers, kids, System.nanoTime());
        return snapshot;
    }

    private Snapshot fresh() throws Exception {
        Snapshot s = snapshot;
        if (s != null && System.nanoTime() - s.fetchedAt <= MAX_STALENESS.toNanos()) {
            return s;
        }
        try {
            return refresh();
        } catch (Exception e) {
            if (s != null) {
                throw new KeyError(KeyError.STALE, "快照已過期且刷新失敗", e);
            }
            throw e;
        }
    }

    /** 以對端系統的公鑰加密。 */
    public String encrypt(String peerSystem, String purpose, byte[] plaintext) throws Exception {
        Snapshot s = fresh();
        if ("disabled".equals(s.mode)) {
            throw new KeyError(KeyError.POLICY_DISABLED, "中央政策為不加密");
        }
        Peer peer = s.peers.get(peerSystem);
        if (peer == null) {
            s = refresh();
            peer = s.peers.get(peerSystem);
            if (peer == null) {
                throw new KeyError(KeyError.UNKNOWN_KID, "對端系統未登記：" + peerSystem);
            }
        }
        return KeyCrypto.encrypt(peer.spki, peer.kid, purpose, plaintext);
    }

    /** 依密文版本取得對應私鑰並解密。 */
    public byte[] decrypt(String token, String purpose) throws Exception {
        Token t = KeyCrypto.parse(token);
        return KeyCrypto.decrypt(privateKey(t.kid), token, purpose);
    }

    private PrivateKey privateKey(String kid) throws Exception {
        PrivateKey cached = privateKeys.get(kid);
        if (cached != null) {
            return cached;
        }
        Snapshot s = snapshot;
        if (s != null && !s.decryptKids.contains(kid)) {
            refresh();
            s = snapshot;
            if (s == null || !s.decryptKids.contains(kid)) {
                throw new KeyError(KeyError.UNKNOWN_KID, "kid 不在授權清單：" + kid);
            }
        }
        String body = "{\"kid\":\"" + kid + "\"}";
        HttpRequest req = HttpRequest.newBuilder(URI.create(cfg.baseUrl + "/api/v1/self/private-key"))
                .header("Content-Type", "application/json")
                .header("User-Agent", USER_AGENT)
                .timeout(Duration.ofSeconds(10))
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                .build();
        HttpResponse<String> res = http.send(req, HttpResponse.BodyHandlers.ofString());

        if (res.statusCode() == 401 || res.statusCode() == 403) {
            throw new KeyError(KeyError.UNAUTHORIZED, "無權取得該私鑰");
        }
        if (res.statusCode() == 404) {
            throw new KeyError(KeyError.UNKNOWN_KID, "kid 不存在：" + kid);
        }
        if (res.statusCode() != 200) {
            throw new KeyError(KeyError.UNAVAILABLE, "私鑰端點回應 " + res.statusCode());
        }
        Map<String, Object> doc = Json.obj(Json.parse(res.body()));
        byte[] der = Base64.getDecoder().decode(Json.str(doc.get("private_key_b64")));
        PrivateKey key = KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(der));
        privateKeys.put(kid, key);
        return key;
    }

    public Snapshot snapshot() {
        return snapshot;
    }

    @Override
    public void close() {
        // HttpClient 無需顯式關閉（Java 17）
    }

    /** 供測試與除錯：目前快取的私鑰版本。 */
    public List<String> cachedKids() {
        return new ArrayList<>(privateKeys.keySet());
    }

    static Map<String, Object> ordered() {
        return new LinkedHashMap<>();
    }
}
