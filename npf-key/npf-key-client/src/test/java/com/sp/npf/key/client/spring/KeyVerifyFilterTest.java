package com.sp.npf.key.client.spring;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicReference;

import javax.servlet.FilterChain;
import javax.servlet.ReadListener;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.sp.npf.key.client.KeyClient;
import com.sp.npf.key.client.KeyClientConfig;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

class KeyVerifyFilterTest {

    private HttpServer server;
    private KeyClient client;
    private KeyVerifyFilter filter;

    @BeforeEach
    void setUp() throws Exception {
        byte[] key = new byte[32];
        for (int i = 0; i < 32; i++) {
            key[i] = (byte) i;
        }
        String json = "{\"etag\":\"v1\",\"refresh\":3600,\"keys\":{\"relay.callback\":{"
                + "\"current\":{\"id\":\"c1\",\"value\":\"" + Base64.getEncoder().encodeToString(key) + "\"},"
                + "\"previous\":null}}}";
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/keys", new HttpHandler() {
            @Override
            public void handle(HttpExchange ex) throws IOException {
                byte[] out = json.getBytes(StandardCharsets.UTF_8);
                ex.sendResponseHeaders(200, out.length);
                try (OutputStream os = ex.getResponseBody()) {
                    os.write(out);
                }
            }
        });
        server.start();
        client = new KeyClient(new KeyClientConfig()
                .baseUrl("http://127.0.0.1:" + server.getAddress().getPort())
                .clientId("npf-payment"));
        client.refreshOnce();
        filter = new KeyVerifyFilter(client, "relay.callback");
    }

    @AfterEach
    void tearDown() {
        client.close();
        server.stop(0);
    }

    @Test
    void passesValidSignatureAndKeepsBodyReadable() throws Exception {
        byte[] body = "{\"orderId\":\"A1\"}".getBytes(StandardCharsets.UTF_8);
        KeyClient.SignResult r = client.sign("relay.callback", body);

        HttpServletRequest req = request(body, Long.toString(r.ts), r.sign);
        HttpServletResponse resp = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);
        AtomicReference<byte[]> seen = new AtomicReference<>();
        org.mockito.Mockito.doAnswer(inv -> {
            ServletRequest wrapper = inv.getArgument(0);
            seen.set(readAll(wrapper));
            return null;
        }).when(chain).doFilter(any(ServletRequest.class), any(ServletResponse.class));

        filter.doFilter(req, resp, chain);

        verify(chain).doFilter(any(ServletRequest.class), eq(resp));
        verify(resp, never()).sendError(anyInt(), anyString());
        assertArrayEquals(body, seen.get(), "controller 应能再读到完整 body");
    }

    @Test
    void rejectsTamperedBody() throws Exception {
        byte[] body = "{\"orderId\":\"A1\"}".getBytes(StandardCharsets.UTF_8);
        KeyClient.SignResult r = client.sign("relay.callback", body);

        HttpServletRequest req = request("{\"orderId\":\"A2\"}".getBytes(StandardCharsets.UTF_8),
                Long.toString(r.ts), r.sign);
        HttpServletResponse resp = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(req, resp, chain);

        verify(resp).sendError(eq(403), anyString());
        verify(chain, never()).doFilter(any(ServletRequest.class), any(ServletResponse.class));
    }

    @Test
    void rejectsMissingTimestamp() throws Exception {
        HttpServletRequest req = request("x".getBytes(StandardCharsets.UTF_8), null, null);
        HttpServletResponse resp = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);
        filter.doFilter(req, resp, chain);
        verify(resp).sendError(eq(403), anyString());
    }

    private static HttpServletRequest request(byte[] body, String ts, String sign) throws IOException {
        HttpServletRequest req = mock(HttpServletRequest.class);
        ServletInputStream in = new ServletInputStream() {
            private final ByteArrayInputStream src = new ByteArrayInputStream(body);

            @Override
            public boolean isFinished() {
                return src.available() == 0;
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setReadListener(ReadListener listener) {
            }

            @Override
            public int read() {
                return src.read();
            }

            @Override
            public int read(byte[] b, int off, int len) {
                return src.read(b, off, len);
            }
        };
        when(req.getInputStream()).thenReturn(in);
        when(req.getHeader("X-Sign-Ts")).thenReturn(ts);
        when(req.getHeader("X-Sign")).thenReturn(sign);
        return req;
    }

    private static byte[] readAll(ServletRequest req) throws IOException {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[1024];
        int n;
        java.io.InputStream in = req.getInputStream();
        while ((n = in.read(buf)) > 0) {
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }
}
