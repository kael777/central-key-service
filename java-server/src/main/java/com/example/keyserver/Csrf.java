package com.example.keyserver;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/** 無狀態 CSRF token：ts.HMAC(secret, ts|role)，有效期 30 分鐘。 */
public final class Csrf {

    private Csrf() {
    }

    public static String issue(byte[] secret, Role role) {
        long ts = System.currentTimeMillis() / 1000;
        String raw = ts + "|" + role.name();
        return ts + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(hmac(secret, raw));
    }

    public static boolean verify(byte[] secret, Role role, String token) {
        if (token == null || token.isBlank()) {
            return false;
        }
        int dot = token.indexOf('.');
        if (dot <= 0) {
            return false;
        }
        long ts;
        try {
            ts = Long.parseLong(token.substring(0, dot));
        } catch (NumberFormatException e) {
            return false;
        }
        long now = System.currentTimeMillis() / 1000;
        if (ts > now + 60 || now - ts > 1800) {
            return false;
        }
        String raw = ts + "|" + role.name();
        String expect = Base64.getUrlEncoder().withoutPadding().encodeToString(hmac(secret, raw));
        return MessageDigest.isEqual(expect.getBytes(StandardCharsets.UTF_8),
                token.substring(dot + 1).getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] hmac(byte[] secret, String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("CSRF 簽章失敗", e);
        }
    }
}
