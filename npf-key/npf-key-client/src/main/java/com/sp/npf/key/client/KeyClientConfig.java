package com.sp.npf.key.client;

/** KeyClient 設定。 */
public class KeyClientConfig {

    private String baseUrl;
    private String clientId;
    private int refreshSeconds = 3600;
    private int jitterSeconds = 300;
    private int retrySeconds = 30;
    private int connectTimeoutMillis = 5000;
    private int readTimeoutMillis = 5000;

    public KeyClientConfig baseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
        return this;
    }

    public KeyClientConfig clientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    public KeyClientConfig refreshSeconds(int refreshSeconds) {
        this.refreshSeconds = refreshSeconds;
        return this;
    }

    public KeyClientConfig jitterSeconds(int jitterSeconds) {
        this.jitterSeconds = jitterSeconds;
        return this;
    }

    public KeyClientConfig retrySeconds(int retrySeconds) {
        this.retrySeconds = retrySeconds;
        return this;
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    public String getClientId() {
        return clientId;
    }

    public int getRefreshSeconds() {
        return refreshSeconds;
    }

    public int getJitterSeconds() {
        return jitterSeconds;
    }

    public int getRetrySeconds() {
        return retrySeconds;
    }

    public int getConnectTimeoutMillis() {
        return connectTimeoutMillis;
    }

    public int getReadTimeoutMillis() {
        return readTimeoutMillis;
    }
}
