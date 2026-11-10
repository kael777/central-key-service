package com.sp.npf.key.client;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;

/**
 * 業務服務內的金鑰客戶端：拉鑰、記憶體快取、雙簽章 sign/verify。
 * 只用 JDK 內建 HTTP 與 javax.crypto，不依賴 Spring。
 */
public class KeyClient implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(KeyClient.class.getName());
    private static final JsonFactory JSON = new JsonFactory();
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int MAX_CLOCK_SKEW_SECONDS = 300;
    private static final long STALE_WARN_MILLIS = 20L * 3600 * 1000;

    private final KeyClientConfig config;
    private final ScheduledExecutorService scheduler;
    private final AtomicBoolean retryScheduled = new AtomicBoolean(false);

    private volatile Map<String, Entry> keys = Collections.emptyMap();
    private volatile String etag;
    private volatile long lastSuccessMillis;

    public KeyClient(KeyClientConfig config) {
        if (config.getBaseUrl() == null || config.getClientId() == null) {
            throw new IllegalArgumentException("baseUrl 與 clientId 必填");
        }
        this.config = config;
        this.scheduler = Executors.newSingleThreadScheduledExecutor(new ThreadFactory() {
            @Override
            public Thread newThread(Runnable r) {
                Thread t = new Thread(r, "npf-key-client");
                t.setDaemon(true);
                return t;
            }
        });
    }

    public void start() {
        scheduler.execute(new Runnable() {
            @Override
            public void run() {
                refreshOnce();
                scheduleNext(config.getRefreshSeconds());
            }
        });
    }

    private void scheduleNext(int seconds) {
        long jitter = config.getJitterSeconds() <= 0 ? 0 : RANDOM.nextInt(config.getJitterSeconds() + 1);
        scheduler.schedule(new Runnable() {
            @Override
            public void run() {
                refreshOnce();
                scheduleNext(config.getRefreshSeconds());
            }
        }, seconds + jitter, TimeUnit.SECONDS);
    }

    /** 立即拉一次；失敗時 30 秒後重試。 */
    public synchronized void refreshOnce() {
        HttpURLConnection conn = null;
        try {
            URL url = new URL(trimSlash(config.getBaseUrl()) + "/keys");
            conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(config.getConnectTimeoutMillis());
            conn.setReadTimeout(config.getReadTimeoutMillis());
            conn.setRequestProperty("X-Client-Id", config.getClientId());
            if (etag != null) {
                conn.setRequestProperty("X-Key-Etag", etag);
            }
            int code = conn.getResponseCode();
            if (code == 304) {
                lastSuccessMillis = System.currentTimeMillis();
                return;
            }
            if (code != 200) {
                throw new IOException("keys endpoint returned " + code);
            }
            byte[] body = readAll(conn.getInputStream());
            Map<String, Entry> parsed = parse(body);
            this.keys = parsed;
            this.lastSuccessMillis = System.currentTimeMillis();
            checkStale();
        } catch (Exception e) {
            LOG.log(Level.WARNING, "[key-service] 拉鑰失敗，沿用記憶體中的鑰", e);
            scheduleRetry();
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    private void scheduleRetry() {
        if (retryScheduled.compareAndSet(false, true)) {
            scheduler.schedule(new Runnable() {
                @Override
                public void run() {
                    retryScheduled.set(false);
                    refreshOnce();
                }
            }, config.getRetrySeconds(), TimeUnit.SECONDS);
        }
    }

    private void checkStale() {
        if (lastSuccessMillis > 0 && System.currentTimeMillis() - lastSuccessMillis > STALE_WARN_MILLIS) {
            LOG.severe("[key-service] 金鑰超過 20 小時未更新");
        }
    }

    /** 用目前與上一把鑰各簽一次，隨機順序接成 64 bytes。 */
    public SignResult sign(String keyName, byte[] body) {
        Entry entry = keys.get(keyName);
        if (entry == null || entry.current == null) {
            throw new IllegalStateException("[key-service] 金鑰未載入：" + keyName);
        }
        long ts = System.currentTimeMillis() / 1000;
        byte[] data = signingData(ts, body);
        byte[] a = hmac(entry.current, data);
        byte[] b = entry.previous != null ? hmac(entry.previous, data) : a;
        byte[] out = new byte[64];
        if (RANDOM.nextBoolean()) {
            System.arraycopy(a, 0, out, 0, 32);
            System.arraycopy(b, 0, out, 32, 32);
        } else {
            System.arraycopy(b, 0, out, 0, 32);
            System.arraycopy(a, 0, out, 32, 32);
        }
        return new SignResult(ts, Base64.getEncoder().encodeToString(out));
    }

    /** 驗簽：時間窗口 300 秒，兩半任一對上目前或上一把即通過。 */
    public boolean verify(String keyName, byte[] body, long ts, String sign) {
        Entry entry = keys.get(keyName);
        if (entry == null || entry.current == null || sign == null) {
            return false;
        }
        long now = System.currentTimeMillis() / 1000;
        if (Math.abs(now - ts) > MAX_CLOCK_SKEW_SECONDS) {
            return false;
        }
        byte[] raw;
        try {
            raw = Base64.getDecoder().decode(sign);
        } catch (IllegalArgumentException e) {
            return false;
        }
        if (raw.length != 64) {
            return false;
        }
        byte[] data = signingData(ts, body);
        byte[] half1 = new byte[32];
        byte[] half2 = new byte[32];
        System.arraycopy(raw, 0, half1, 0, 32);
        System.arraycopy(raw, 32, half2, 0, 32);
        byte[] c = hmac(entry.current, data);
        if (MessageDigest.isEqual(half1, c) || MessageDigest.isEqual(half2, c)) {
            return true;
        }
        if (entry.previous != null) {
            byte[] p = hmac(entry.previous, data);
            return MessageDigest.isEqual(half1, p) || MessageDigest.isEqual(half2, p);
        }
        return false;
    }

    public boolean hasKey(String keyName) {
        Entry e = keys.get(keyName);
        return e != null && e.current != null;
    }

    public long lastSuccessMillis() {
        return lastSuccessMillis;
    }

    private static byte[] signingData(long ts, byte[] body) {
        byte[] prefix = (ts + "\n").getBytes(StandardCharsets.UTF_8);
        byte[] data = new byte[prefix.length + (body == null ? 0 : body.length)];
        System.arraycopy(prefix, 0, data, 0, prefix.length);
        if (body != null) {
            System.arraycopy(body, 0, data, prefix.length, body.length);
        }
        return data;
    }

    private static byte[] hmac(byte[] key, byte[] data) {
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private Map<String, Entry> parse(byte[] body) throws IOException {
        Map<String, Entry> result = new HashMap<>();
        try (JsonParser p = JSON.createParser(body)) {
            if (p.nextToken() != JsonToken.START_OBJECT) {
                throw new IOException("invalid keys response");
            }
            while (p.nextToken() == JsonToken.FIELD_NAME) {
                String field = p.getCurrentName();
                p.nextToken();
                if ("etag".equals(field)) {
                    this.etag = p.getText();
                } else if ("keys".equals(field)) {
                    parseKeys(p, result);
                } else {
                    p.skipChildren();
                }
            }
        }
        return result;
    }

    private void parseKeys(JsonParser p, Map<String, Entry> result) throws IOException {
        if (p.currentToken() != JsonToken.START_OBJECT) {
            p.skipChildren();
            return;
        }
        while (p.nextToken() == JsonToken.FIELD_NAME) {
            String name = p.getCurrentName();
            p.nextToken();
            Entry e = new Entry();
            if (p.currentToken() == JsonToken.START_OBJECT) {
                while (p.nextToken() == JsonToken.FIELD_NAME) {
                    String which = p.getCurrentName();
                    p.nextToken();
                    if ("current".equals(which)) {
                        e.current = readValue(p);
                    } else if ("previous".equals(which)) {
                        e.previous = readValue(p);
                    } else {
                        p.skipChildren();
                    }
                }
            } else {
                p.skipChildren();
            }
            result.put(name, e);
        }
    }

    private byte[] readValue(JsonParser p) throws IOException {
        if (p.currentToken() == JsonToken.VALUE_NULL) {
            return null;
        }
        if (p.currentToken() != JsonToken.START_OBJECT) {
            p.skipChildren();
            return null;
        }
        String value = null;
        while (p.nextToken() == JsonToken.FIELD_NAME) {
            String field = p.getCurrentName();
            p.nextToken();
            if ("value".equals(field)) {
                value = p.getText();
            } else {
                p.skipChildren();
            }
        }
        return value == null ? null : Base64.getDecoder().decode(value);
    }

    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) > 0) {
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }

    private static String trimSlash(String s) {
        return s.endsWith("/") ? s.substring(0, s.length() - 1) : s;
    }

    @Override
    public void close() {
        scheduler.shutdownNow();
    }

    private static class Entry {
        byte[] current;
        byte[] previous;
    }

    public static class SignResult {
        public final long ts;
        public final String sign;

        public SignResult(long ts, String sign) {
            this.ts = ts;
            this.sign = sign;
        }
    }

    /** 測試／診斷用：目前載入的鑰名。 */
    public Map<String, Boolean> loadedKeys() {
        Map<String, Boolean> m = new LinkedHashMap<>();
        for (Map.Entry<String, Entry> e : keys.entrySet()) {
            m.put(e.getKey(), e.getValue().previous != null);
        }
        return m;
    }
}
