package com.sp.npf.key.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

class KeyClientEtagFailureTest {

    private HttpServer server;
    private KeyClient client;
    private final AtomicReference<String> body = new AtomicReference<>();
    private final AtomicReference<String> etagHeader = new AtomicReference<>();
    private final AtomicReference<String> seenEtag = new AtomicReference<>();

    @BeforeEach
    void setUp() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/keys", new HttpHandler() {
            @Override
            public void handle(HttpExchange ex) throws IOException {
                seenEtag.set(ex.getRequestHeaders().getFirst("X-Key-Etag"));
                byte[] out = body.get().getBytes(StandardCharsets.UTF_8);
                ex.getResponseHeaders().add("ETag", etagHeader.get());
                ex.sendResponseHeaders(200, out.length);
                try (OutputStream os = ex.getResponseBody()) {
                    os.write(out);
                }
            }
        });
        server.start();
        body.set(good("v1"));
        etagHeader.set("v1");
        client = new KeyClient(new KeyClientConfig()
                .baseUrl("http://127.0.0.1:" + server.getAddress().getPort())
                .clientId("npf-payment"));
        client.refreshOnce();
        assertNull(seenEtag.get(), "第一次應不帶 etag");
    }

    @AfterEach
    void tearDown() {
        client.close();
        server.stop(0);
    }

    @Test
    void malformedResponseDoesNotAdvanceEtag() {
        body.set("{not-json");
        etagHeader.set("v2");
        assertFalse(client.refreshOnce(), "壞掉的回應應失敗");

        body.set(good("v1"));
        etagHeader.set("v1");
        client.refreshOnce();
        assertEquals("v1", seenEtag.get(), "壞回應後仍應帶舊 etag，不能卡在 304");
    }

    private static String good(String tag) {
        return "{\"etag\":\"" + tag + "\",\"refresh\":3600,\"keys\":{}}";
    }
}
