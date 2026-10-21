package com.example.keyserver;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class OidcTest {

    private static String b64(byte[] b) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    private static String sign(KeyPair kp, String header, String payload) throws Exception {
        String input = b64(header.getBytes(StandardCharsets.UTF_8)) + "." + b64(payload.getBytes(StandardCharsets.UTF_8));
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(kp.getPrivate());
        s.update(input.getBytes(StandardCharsets.US_ASCII));
        return input + "." + b64(s.sign());
    }

    private static AppConfig config() {
        AppConfig cfg = new AppConfig();
        cfg.oidcIssuer = "https://idp.example.com";
        cfg.oidcClientId = "cms";
        cfg.oidcGroupRoles = "cms-admins=admin,cms-ops=operator";
        cfg.oidcDefaultRole = "viewer";
        cfg.oidcGroupsClaim = "groups";
        return cfg;
    }

    @Test
    void verifiesRs256AndMapsRole() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        AppConfig cfg = config();
        Oidc oidc = new Oidc(cfg);

        long exp = System.currentTimeMillis() / 1000 + 600;
        String payload = "{\"iss\":\"https://idp.example.com\",\"aud\":\"cms\",\"exp\":" + exp
                + ",\"nonce\":\"n1\",\"sub\":\"u1\",\"preferred_username\":\"alice\","
                + "\"groups\":[\"cms-ops\",\"cms-admins\"]}";
        String token = sign(kp, "{\"alg\":\"RS256\",\"kid\":\"k1\",\"typ\":\"JWT\"}", payload);

        Map<String, PublicKey> keys = new LinkedHashMap<>();
        keys.put("k1", kp.getPublic());
        Map<String, Object> claims = oidc.verifyJwt(token, keys, "n1");
        assertEquals("alice", claims.get("preferred_username"));
        assertEquals(Role.ADMIN, oidc.roleFor(claims));
    }

    @Test
    void rejectsTamperedPayload() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        Oidc oidc = new Oidc(config());

        long exp = System.currentTimeMillis() / 1000 + 600;
        String payload = "{\"iss\":\"https://idp.example.com\",\"aud\":\"cms\",\"exp\":" + exp + ",\"nonce\":\"n1\"}";
        String token = sign(kp, "{\"alg\":\"RS256\",\"kid\":\"k1\"}", payload);

        String[] parts = token.split("\\.");
        String evilJson = "{\"iss\":\"https://idp.example.com\",\"aud\":\"cms\",\"exp\":" + exp + ",\"groups\":[\"cms-admins\"]}";
        String evil = b64(evilJson.getBytes(StandardCharsets.UTF_8));
        String tampered = parts[0] + "." + evil + "." + parts[2];

        Map<String, PublicKey> keys = Map.of("k1", kp.getPublic());
        assertThrows(IllegalArgumentException.class, () -> oidc.verifyJwt(tampered, keys, "n1"));
    }

    @Test
    void rejectsWrongAudience() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        Oidc oidc = new Oidc(config());

        long exp = System.currentTimeMillis() / 1000 + 600;
        String payload = "{\"iss\":\"https://idp.example.com\",\"aud\":\"other\",\"exp\":" + exp + ",\"nonce\":\"n1\"}";
        String token = sign(kp, "{\"alg\":\"RS256\",\"kid\":\"k1\"}", payload);
        assertThrows(IllegalArgumentException.class,
                () -> oidc.verifyJwt(token, Map.of("k1", kp.getPublic()), "n1"));
    }

    @Test
    void csrfAndSessionRoundTrip() {
        byte[] secret = "test-secret".getBytes(StandardCharsets.UTF_8);
        String csrf = Csrf.issue(secret, Role.OPERATOR);
        org.junit.jupiter.api.Assertions.assertTrue(Csrf.verify(secret, Role.OPERATOR, csrf));
        org.junit.jupiter.api.Assertions.assertFalse(Csrf.verify(secret, Role.ADMIN, csrf));

        Map<String, Object> payload = Map.of("sub", "alice", "role", "admin",
                "exp", System.currentTimeMillis() / 1000 + 60);
        String cookie = Session.sign(secret, payload);
        assertEquals("admin", Session.verify(secret, cookie).get("role"));
        org.junit.jupiter.api.Assertions.assertNull(Session.verify(secret, cookie + "x"));
    }

    @Test
    void roleMappingDefaultsToViewer() {
        Oidc oidc = new Oidc(config());
        assertEquals(Role.VIEWER, oidc.roleFor(Map.of("groups", List.of("others"))));
        assertEquals(Role.OPERATOR, oidc.roleFor(Map.of("groups", List.of("cms-ops"))));
    }
}
