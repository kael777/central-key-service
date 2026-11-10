package com.sp.npf.key.client.spring;

import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "npf.key.client")
public class NpfKeyClientProperties {

    private String baseUrl;
    private String clientId;
    private int refreshSeconds = 3600;
    private int jitterSeconds = 300;
    private String verifyKeyName;
    private List<String> verifyPaths = new ArrayList<>();

    public String getBaseUrl() {
        return baseUrl;
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public int getRefreshSeconds() {
        return refreshSeconds;
    }

    public void setRefreshSeconds(int refreshSeconds) {
        this.refreshSeconds = refreshSeconds;
    }

    public int getJitterSeconds() {
        return jitterSeconds;
    }

    public void setJitterSeconds(int jitterSeconds) {
        this.jitterSeconds = jitterSeconds;
    }

    public String getVerifyKeyName() {
        return verifyKeyName;
    }

    public void setVerifyKeyName(String verifyKeyName) {
        this.verifyKeyName = verifyKeyName;
    }

    public List<String> getVerifyPaths() {
        return verifyPaths;
    }

    public void setVerifyPaths(List<String> verifyPaths) {
        this.verifyPaths = verifyPaths;
    }
}
