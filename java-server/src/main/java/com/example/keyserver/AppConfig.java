package com.example.keyserver;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AppConfig {

    @Value("${app.admin-token:dev-token}")
    public String adminToken;

    @Value("${app.operator-token:}")
    public String operatorToken;

    @Value("${app.viewer-token:}")
    public String viewerToken;

    @Value("${app.session-secret:}")
    public String sessionSecret;

    @Value("${app.kek:}")
    public String kekHex;

    @Value("${app.grace-seconds:300}")
    public long graceSeconds;

    @Value("${app.prepublish-seconds:600}")
    public long prepublishSeconds;

    @Value("${app.rotation-seconds:3600}")
    public long rotationSeconds;

    @Value("${app.require-ip-allow:true}")
    public boolean requireIpAllow;

    @Value("${app.max-decrypt:8}")
    public int maxDecrypt;

    @Value("${app.retention-seconds:2592000}")
    public long retentionSeconds;

    @Value("${app.retention-keep:20}")
    public int retentionKeep;

    @Value("${app.trusted-proxies:}")
    public String trustedProxies;

    @Value("${app.proxy-secret:}")
    public String proxySecret;

    // ---------- OIDC ----------

    @Value("${app.oidc.issuer:}")
    public String oidcIssuer;

    @Value("${app.oidc.client-id:}")
    public String oidcClientId;

    @Value("${app.oidc.client-secret:}")
    public String oidcClientSecret;

    @Value("${app.oidc.redirect-uri:}")
    public String oidcRedirectUri;

    @Value("${app.oidc.groups-claim:groups}")
    public String oidcGroupsClaim;

    @Value("${app.oidc.default-role:viewer}")
    public String oidcDefaultRole;

    @Value("${app.oidc.group-roles:}")
    public String oidcGroupRoles;

    public boolean oidcEnabled() {
        return oidcIssuer != null && !oidcIssuer.isBlank();
    }

    public byte[] csrfSecret() {
        String s = sessionSecret == null || sessionSecret.isBlank() ? adminToken : sessionSecret;
        return s.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }
}
