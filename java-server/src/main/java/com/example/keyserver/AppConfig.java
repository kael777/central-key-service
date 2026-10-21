package com.example.keyserver;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AppConfig {

    @Value("${app.admin-token:dev-token}")
    public String adminToken;

    @Value("${app.kek:}")
    public String kekHex;

    @Value("${app.grace-seconds:300}")
    public long graceSeconds;

    @Value("${app.prepublish-seconds:600}")
    public long prepublishSeconds;

    @Value("${app.rotation-seconds:3600}")
    public long rotationSeconds;

    @Value("${app.trusted-proxies:}")
    public String trustedProxies;

    @Value("${app.proxy-secret:}")
    public String proxySecret;
}
