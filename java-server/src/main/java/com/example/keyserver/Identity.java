package com.example.keyserver;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.security.cert.X509Certificate;

/** 身分解析：直連 mTLS 取 CN；受信代理則讀轉發標頭。 */
@Component
public class Identity {

    private final AppConfig cfg;

    public Identity(AppConfig cfg) {
        this.cfg = cfg;
    }

    public String requireSystem(HttpServletRequest req) {
        X509Certificate[] certs = (X509Certificate[]) req.getAttribute("jakarta.servlet.request.X509Certificate");
        if (certs != null && certs.length > 0) {
            String cn = cn(certs[0]);
            if (cn != null && !cn.isBlank()) {
                return cn;
            }
            throw new ApiException(401, "no_identity", "缺少用戶端憑證");
        }
        String remote = req.getRemoteAddr();
        if (!trustedProxy(remote)) {
            throw new ApiException(401, "no_identity", "缺少用戶端憑證");
        }
        if (!cfg.proxySecret.isBlank()) {
            String got = req.getHeader("X-Proxy-Secret");
            if (got == null || !constantEquals(got, cfg.proxySecret)) {
                throw new ApiException(401, "bad_proxy_secret", "代理密鑰不符");
            }
        }
        String verify = req.getHeader("X-Client-Verify");
        if (verify == null || !verify.trim().equalsIgnoreCase("SUCCESS")) {
            throw new ApiException(401, "not_verified", "代理未驗證用戶端憑證");
        }
        String cn = normalizeCn(req.getHeader("X-Client-CN"));
        if (cn == null || cn.isBlank()) {
            throw new ApiException(401, "no_identity", "缺少用戶端憑證");
        }
        return cn;
    }

    public String clientIp(HttpServletRequest req) {
        if (trustedProxy(req.getRemoteAddr())) {
            String xff = req.getHeader("X-Forwarded-For");
            if (xff != null && !xff.isBlank()) {
                String first = xff.split(",")[0].trim();
                if (!first.isEmpty()) {
                    return first;
                }
            }
        }
        return req.getRemoteAddr();
    }

    public boolean trustedProxy(String remote) {
        if (cfg.trustedProxies == null || cfg.trustedProxies.isBlank()) {
            return false;
        }
        String ip = remote == null ? "" : remote;
        for (String rule : cfg.trustedProxies.split(",")) {
            if (IpRules.matches(rule.trim(), ip)) {
                return true;
            }
        }
        return false;
    }

    private static String cn(X509Certificate cert) {
        try {
            LdapName dn = new LdapName(cert.getSubjectX500Principal().getName());
            for (Rdn rdn : dn.getRdns()) {
                if ("CN".equalsIgnoreCase(rdn.getType())) {
                    return String.valueOf(rdn.getValue()).trim();
                }
            }
        } catch (Exception ignored) {
            // fall through
        }
        String name = cert.getSubjectX500Principal().getName();
        for (String part : name.split(",")) {
            String p = part.trim();
            if (p.regionMatches(true, 0, "CN=", 0, 3)) {
                return p.substring(3).trim();
            }
        }
        return null;
    }

    /** 兼容完整 DN（/C=CN/O=x/CN=SYS-A）與純 CN。 */
    static String normalizeCn(String raw) {
        if (raw == null) {
            return null;
        }
        String s = raw.trim();
        if (!s.contains("CN=")) {
            return s;
        }
        for (String part : s.split("[/,]")) {
            String p = part.trim();
            if (p.regionMatches(true, 0, "CN=", 0, 3)) {
                return p.substring(3).trim();
            }
        }
        return s;
    }

    private static boolean constantEquals(String a, String b) {
        byte[] x = a.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] y = b.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        if (x.length != y.length) {
            return false;
        }
        int diff = 0;
        for (int i = 0; i < x.length; i++) {
            diff |= x[i] ^ y[i];
        }
        return diff == 0;
    }
}
