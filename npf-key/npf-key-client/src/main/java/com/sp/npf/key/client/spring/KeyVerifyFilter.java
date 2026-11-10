package com.sp.npf.key.client.spring;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.ReadListener;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

import com.sp.npf.key.client.KeyClient;

/**
 * 對指定路徑驗 X-Sign-Ts / X-Sign，通過後把可重讀的 body 交給 controller。
 * 由 KeyClientAutoConfiguration 依 npf.key.client.verify-paths 註冊。
 */
public class KeyVerifyFilter implements Filter {

    private final KeyClient client;
    private final String keyName;

    public KeyVerifyFilter(KeyClient client, String keyName) {
        this.client = client;
        this.keyName = keyName;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse resp = (HttpServletResponse) response;

        byte[] body = readAll(req);
        String tsHeader = req.getHeader("X-Sign-Ts");
        String sign = req.getHeader("X-Sign");
        long ts;
        try {
            ts = Long.parseLong(tsHeader);
        } catch (Exception e) {
            resp.sendError(HttpServletResponse.SC_FORBIDDEN, "invalid X-Sign-Ts");
            return;
        }
        if (!client.verify(keyName, body, ts, sign)) {
            resp.sendError(HttpServletResponse.SC_FORBIDDEN, "invalid signature");
            return;
        }
        chain.doFilter(new CachedBodyRequest(req, body), resp);
    }

    private static byte[] readAll(HttpServletRequest req) throws IOException {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        java.io.InputStream in = req.getInputStream();
        while ((n = in.read(buf)) > 0) {
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }

    /** body 只讀一次，包成可重複讀取。 */
    private static class CachedBodyRequest extends HttpServletRequestWrapper {

        private final byte[] body;

        CachedBodyRequest(HttpServletRequest request, byte[] body) {
            super(request);
            this.body = body;
        }

        @Override
        public ServletInputStream getInputStream() {
            final ByteArrayInputStream in = new ByteArrayInputStream(body);
            return new ServletInputStream() {
                @Override
                public boolean isFinished() {
                    return in.available() == 0;
                }

                @Override
                public boolean isReady() {
                    return true;
                }

                @Override
                public void setReadListener(ReadListener listener) {
                    // 同步過濾器不需要
                }

                @Override
                public int read() {
                    return in.read();
                }

                @Override
                public int read(byte[] b, int off, int len) {
                    return in.read(b, off, len);
                }
            };
        }

        @Override
        public BufferedReader getReader() {
            return new BufferedReader(new InputStreamReader(new ByteArrayInputStream(body), StandardCharsets.UTF_8));
        }
    }
}
