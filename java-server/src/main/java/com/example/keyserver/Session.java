package com.example.keyserver;

import com.fasterxml.jackson.databind.ObjectMapper;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Map;

/** 簽章 cookie：base64url(json).base64url(HMAC)。 */
public final class Session {

    private static final ObjectMapper JSON = new ObjectMapper();

    private Session() {
    }

    public static String sign(byte[] secret, Map<String, Object> payload) {
        try {
            String body = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(JSON.writeValueAsBytes(payload));
            return body + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(hmac(secret, body));
        } catch (Exception e) {
            throw new IllegalStateException("簽章失敗", e);
        }
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> verify(byte[] secret, String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        int dot = value.lastIndexOf('.');
        if (dot <= 0) {
            return null;
        }
        String body = value.substring(0, dot);
        String sig = value.substring(dot + 1);
        String expect = Base64.getUrlEncoder().withoutPadding().encodeToString(hmac(secret, body));
        if (!MessageDigest.isEqual(expect.getBytes(StandardCharsets.UTF_8), sig.getBytes(StandardCharsets.UTF_8))) {
            return null;
        }
        try {
            Map<String, Object> payload = JSON.readValue(Base64.getUrlDecoder().decode(body), Map.class);
            Object exp = payload.get("exp");
            if (exp instanceof Number n && n.longValue() < System.currentTimeMillis() / 1000) {
                return null;
            }
            return payload;
        } catch (Exception e) {
            return null;
        }
    }

    private static byte[] hmac(byte[] secret, String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("HMAC 失敗", e);
        }
    }
}
