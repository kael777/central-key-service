package com.example.keyserver;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** OIDC 授權碼流程（含 PKCE、JWKS 簽章驗證）。 */
@Component
public class Oidc {

    private static final Logger log = LoggerFactory.getLogger(Oidc.class);
    private static final ObjectMapper JSON = new ObjectMapper();

    private final AppConfig cfg;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    private volatile Map<String, Object> discovery;
    private volatile long discoveryAt;
    private volatile Map<String, PublicKey> jwks = Map.of();
    private volatile long jwksAt;

    public Oidc(AppConfig cfg) {
        this.cfg = cfg;
    }

    public boolean enabled() {
        return cfg.oidcEnabled();
    }

    @SuppressWarnings("unchecked")
    public synchronized Map<String, Object> discovery() throws Exception {
        long now = System.currentTimeMillis();
        if (discovery != null && now - discoveryAt < 3_600_000) {
            return discovery;
        }
        String url = cfg.oidcIssuer.replaceAll("/$", "") + "/.well-known/openid-configuration";
        HttpRequest req = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(10)).GET().build();
        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200) {
            throw new IllegalStateException("OIDC discovery 失敗：" + resp.statusCode());
        }
        discovery = JSON.readValue(resp.body(), Map.class);
        discoveryAt = now;
        return discovery;
    }

    public String authorizeUrl(String state, String nonce, String verifier) throws Exception {
        Map<String, Object> d = discovery();
        String endpoint = String.valueOf(d.get("authorization_endpoint"));
        String challenge = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(java.security.MessageDigest.getInstance("SHA-256")
                        .digest(verifier.getBytes(StandardCharsets.US_ASCII)));
        return endpoint
                + "?response_type=code"
                + "&client_id=" + enc(cfg.oidcClientId)
                + "&redirect_uri=" + enc(cfg.oidcRedirectUri)
                + "&scope=" + enc("openid profile email")
                + "&state=" + enc(state)
                + "&nonce=" + enc(nonce)
                + "&code_challenge=" + enc(challenge)
                + "&code_challenge_method=S256";
    }

    @SuppressWarnings("unchecked")
    public String exchangeCode(String code, String verifier) throws Exception {
        Map<String, Object> d = discovery();
        String endpoint = String.valueOf(d.get("token_endpoint"));
        String form = "grant_type=authorization_code"
                + "&code=" + enc(code)
                + "&redirect_uri=" + enc(cfg.oidcRedirectUri)
                + "&client_id=" + enc(cfg.oidcClientId)
                + "&client_secret=" + enc(cfg.oidcClientSecret)
                + "&code_verifier=" + enc(verifier);
        HttpRequest req = HttpRequest.newBuilder(URI.create(endpoint))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .timeout(Duration.ofSeconds(10))
                .POST(HttpRequest.BodyPublishers.ofString(form)).build();
        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200) {
            throw new IllegalStateException("換取 token 失敗：" + resp.statusCode() + " " + resp.body());
        }
        Map<String, Object> body = JSON.readValue(resp.body(), Map.class);
        Object idToken = body.get("id_token");
        if (idToken == null) {
            throw new IllegalStateException("回應缺少 id_token");
        }
        return String.valueOf(idToken);
    }

    public Map<String, Object> verifyIdToken(String idToken, String expectedNonce) throws Exception {
        try {
            return verifyJwt(idToken, keys(), expectedNonce);
        } catch (IllegalArgumentException e) {
            if (!e.getMessage().contains("JWKS")) {
                throw e;
            }
            refreshJwks();
            return verifyJwt(idToken, jwks, expectedNonce);
        }
    }

    @SuppressWarnings("unchecked")
    Map<String, Object> verifyJwt(String idToken, Map<String, PublicKey> keys, String expectedNonce) throws Exception {
        String[] parts = idToken.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("id_token 格式錯誤");
        }
        Map<String, Object> header = JSON.readValue(Base64.getUrlDecoder().decode(parts[0]), Map.class);
        String alg = String.valueOf(header.get("alg"));
        String kid = header.get("kid") == null ? null : String.valueOf(header.get("kid"));
        PublicKey key = kid != null ? keys.get(kid) : (keys.isEmpty() ? null : keys.values().iterator().next());
        if (key == null) {
            throw new IllegalArgumentException("找不到對應的 JWKS 公鑰");
        }
        byte[] signingInput = (parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII);
        byte[] sig = Base64.getUrlDecoder().decode(parts[2]);
        boolean ok = switch (alg) {
            case "RS256" -> verifyRsa(key, signingInput, sig);
            case "ES256" -> verifyEcdsa(key, signingInput, sig);
            default -> throw new IllegalArgumentException("不支援的 alg：" + alg);
        };
        if (!ok) {
            throw new IllegalArgumentException("id_token 簽章驗證失敗");
        }
        Map<String, Object> claims = JSON.readValue(Base64.getUrlDecoder().decode(parts[1]), Map.class);
        String iss = String.valueOf(claims.get("iss"));
        if (!iss.replaceAll("/$", "").equals(cfg.oidcIssuer.replaceAll("/$", ""))) {
            throw new IllegalArgumentException("issuer 不符");
        }
        if (!audienceOk(claims.get("aud"))) {
            throw new IllegalArgumentException("audience 不符");
        }
        long exp = ((Number) claims.getOrDefault("exp", 0)).longValue();
        if (exp * 1000 < System.currentTimeMillis() - 120_000) {
            throw new IllegalArgumentException("id_token 已過期");
        }
        if (expectedNonce != null && claims.get("nonce") != null
                && !expectedNonce.equals(String.valueOf(claims.get("nonce")))) {
            throw new IllegalArgumentException("nonce 不符");
        }
        return claims;
    }

    @SuppressWarnings("unchecked")
    public Role roleFor(Map<String, Object> claims) {
        Role fallback = Role.parse(cfg.oidcDefaultRole, Role.VIEWER);
        Object raw = claims.get(cfg.oidcGroupsClaim);
        List<String> groups = new ArrayList<>();
        if (raw instanceof List<?> list) {
            for (Object o : list) {
                groups.add(String.valueOf(o));
            }
        } else if (raw instanceof String s && !s.isBlank()) {
            groups.add(s);
        }
        Role best = null;
        for (String entry : cfg.oidcGroupRoles.split(",")) {
            if (entry.isBlank()) {
                continue;
            }
            String[] kv = entry.split("=", 2);
            if (kv.length != 2) {
                continue;
            }
            String group = kv[0].trim();
            Role role = Role.parse(kv[1], null);
            if (role != null && groups.contains(group) && (best == null || role.level() > best.level())) {
                best = role;
            }
        }
        return best != null ? best : fallback;
    }

    // ---------- 內部 ----------

    private boolean audienceOk(Object aud) {
        if (aud instanceof String s) {
            return s.equals(cfg.oidcClientId);
        }
        if (aud instanceof List<?> list) {
            return list.stream().anyMatch(o -> cfg.oidcClientId.equals(String.valueOf(o)));
        }
        return false;
    }

    private boolean verifyRsa(PublicKey key, byte[] input, byte[] sig) throws Exception {
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initVerify(key);
        s.update(input);
        return s.verify(sig);
    }

    private boolean verifyEcdsa(PublicKey key, byte[] input, byte[] sig) throws Exception {
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initVerify(key);
        s.update(input);
        return s.verify(rawToDer(sig));
    }

    /** JWS 的 ES256 是 r||s，Java Signature 要 DER。 */
    static byte[] rawToDer(byte[] raw) {
        if (raw.length != 64) {
            return raw;
        }
        byte[] r = new byte[32];
        byte[] s = new byte[32];
        System.arraycopy(raw, 0, r, 0, 32);
        System.arraycopy(raw, 32, s, 0, 32);
        byte[] rb = trim(new BigInteger(1, r).toByteArray());
        byte[] sb = trim(new BigInteger(1, s).toByteArray());
        int len = 2 + rb.length + 2 + sb.length;
        byte[] out = new byte[2 + len];
        out[0] = 0x30;
        out[1] = (byte) len;
        out[2] = 0x02;
        out[3] = (byte) rb.length;
        System.arraycopy(rb, 0, out, 4, rb.length);
        int off = 4 + rb.length;
        out[off] = 0x02;
        out[off + 1] = (byte) sb.length;
        System.arraycopy(sb, 0, out, off + 2, sb.length);
        return out;
    }

    private static byte[] trim(byte[] in) {
        return in.length > 1 && in[0] == 0 ? java.util.Arrays.copyOfRange(in, 1, in.length) : in;
    }

    @SuppressWarnings("unchecked")
    private synchronized Map<String, PublicKey> keys() throws Exception {
        long now = System.currentTimeMillis();
        if (!jwks.isEmpty() && now - jwksAt < 3_600_000) {
            return jwks;
        }
        refreshJwks();
        return jwks;
    }

    @SuppressWarnings("unchecked")
    private void refreshJwks() throws Exception {
        Map<String, Object> d = discovery();
        String uri = String.valueOf(d.get("jwks_uri"));
        HttpRequest req = HttpRequest.newBuilder(URI.create(uri)).timeout(Duration.ofSeconds(10)).GET().build();
        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200) {
            throw new IllegalStateException("取得 JWKS 失敗：" + resp.statusCode());
        }
        Map<String, Object> body = JSON.readValue(resp.body(), Map.class);
        List<Map<String, Object>> list = (List<Map<String, Object>>) body.get("keys");
        Map<String, PublicKey> out = new LinkedHashMap<>();
        if (list != null) {
            for (Map<String, Object> k : list) {
                try {
                    String kid = String.valueOf(k.get("kid"));
                    PublicKey pk = toPublicKey(k);
                    if (pk != null) {
                        out.put(kid, pk);
                    }
                } catch (Exception e) {
                    log.warn("略過無法解析的 JWK：{}", e.getMessage());
                }
            }
        }
        jwks = out;
        jwksAt = System.currentTimeMillis();
    }

    private PublicKey toPublicKey(Map<String, Object> k) throws Exception {
        String kty = String.valueOf(k.get("kty"));
        if ("RSA".equals(kty)) {
            BigInteger n = new BigInteger(1, Base64.getUrlDecoder().decode(String.valueOf(k.get("n"))));
            BigInteger e = new BigInteger(1, Base64.getUrlDecoder().decode(String.valueOf(k.get("e"))));
            return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));
        }
        if ("EC".equals(kty)) {
            BigInteger x = new BigInteger(1, Base64.getUrlDecoder().decode(String.valueOf(k.get("x"))));
            BigInteger y = new BigInteger(1, Base64.getUrlDecoder().decode(String.valueOf(k.get("y"))));
            java.security.AlgorithmParameters ap = java.security.AlgorithmParameters.getInstance("EC");
            ap.init(new java.security.spec.ECGenParameterSpec("secp256r1"));
            java.security.spec.ECParameterSpec spec = ap.getParameterSpec(java.security.spec.ECParameterSpec.class);
            return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(x, y), spec));
        }
        return null;
    }

    private static String enc(String s) {
        return URLEncoder.encode(s == null ? "" : s, StandardCharsets.UTF_8);
    }
}
