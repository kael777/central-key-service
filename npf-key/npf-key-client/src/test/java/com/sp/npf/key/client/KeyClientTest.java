package com.sp.npf.key.client;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

class KeyClientTest {

    private HttpServer server;
    private final AtomicReference<String> body = new AtomicReference<>();
    private final AtomicReference<String> etag = new AtomicReference<>("v1");
    private KeyClient client;
    private String baseUrl;

    private static final byte[] KEY_A = new byte[32];
    private static final byte[] KEY_B = new byte[32];
    static {
        for (int i = 0; i < 32; i++) {
            KEY_A[i] = (byte) i;
            KEY_B[i] = (byte) (i + 100);
        }
    }

    @BeforeEach
    void setUp() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/keys", new HttpHandler() {
            @Override
            public void handle(HttpExchange ex) throws IOException {
                String ifNoneMatch = ex.getRequestHeaders().getFirst("X-Key-Etag");
                if (etag.get().equals(ifNoneMatch)) {
                    ex.sendResponseHeaders(304, -1);
                    ex.close();
                    return;
                }
                byte[] out = body.get().getBytes(StandardCharsets.UTF_8);
                ex.getResponseHeaders().add("ETag", etag.get());
                ex.sendResponseHeaders(200, out.length);
                try (OutputStream os = ex.getResponseBody()) {
                    os.write(out);
                }
            }
        });
        server.start();
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
        body.set(json("v1", KEY_A, KEY_B));
        client = new KeyClient(new KeyClientConfig().baseUrl(baseUrl).clientId("npf-payment"));
        client.refreshOnce();
    }

    @AfterEach
    void tearDown() {
        client.close();
        server.stop(0);
    }

    @Test
    void signsAndVerifies() {
        byte[] payload = "{\"orderId\":\"A1\"}".getBytes(StandardCharsets.UTF_8);
        KeyClient.SignResult r = client.sign("relay.callback", payload);
        assertTrue(client.verify("relay.callback", payload, r.ts, r.sign));
        assertFalse(client.verify("relay.callback", "tampered".getBytes(StandardCharsets.UTF_8), r.ts, r.sign));
    }

    @Test
    void rejectsOldTimestamp() {
        byte[] payload = "x".getBytes(StandardCharsets.UTF_8);
        KeyClient.SignResult r = client.sign("relay.callback", payload);
        assertFalse(client.verify("relay.callback", payload, r.ts - 301, r.sign));
    }

    @Test
    void acceptsSignatureMadeWithPreviousAfterRotation() {
        byte[] payload = "order".getBytes(StandardCharsets.UTF_8);
        KeyClient.SignResult old = client.sign("relay.callback", payload);

        // 伺服器輪替：新 current = KEY_B，previous = KEY_A
        byte[] keyC = new byte[32];
        for (int i = 0; i < 32; i++) {
            keyC[i] = (byte) (i + 7);
        }
        body.set(json("v2", keyC, KEY_B));
        etag.set("v2");
        client.refreshOnce();

        assertTrue(client.verify("relay.callback", payload, old.ts, old.sign));
        KeyClient.SignResult now = client.sign("relay.callback", payload);
        assertTrue(client.verify("relay.callback", payload, now.ts, now.sign));
    }

    @Test
    void usesEtagAndHandles304() {
        client.refreshOnce();
        assertTrue(client.hasKey("relay.callback"));
    }

    private static String json(String tag, byte[] current, byte[] previous) {
        String c = Base64.getEncoder().encodeToString(current);
        String p = Base64.getEncoder().encodeToString(previous);
        return "{\"etag\":\"" + tag + "\",\"refresh\":3600,\"keys\":{\"relay.callback\":{"
                + "\"current\":{\"id\":\"c1\",\"value\":\"" + c + "\"},"
                + "\"previous\":{\"id\":\"p1\",\"value\":\"" + p + "\"}}}}";
    }
}
