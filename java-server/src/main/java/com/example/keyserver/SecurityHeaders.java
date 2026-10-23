package com.example.keyserver;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;

/** 後台頁面的基本安全標頭。 */
@Component
public class SecurityHeaders implements Filter {

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws java.io.IOException, jakarta.servlet.ServletException {
        if (res instanceof HttpServletResponse r) {
            r.setHeader("X-Frame-Options", "DENY");
            r.setHeader("X-Content-Type-Options", "nosniff");
            r.setHeader("Referrer-Policy", "no-referrer");
            r.setHeader("Content-Security-Policy",
                    "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'");
        }
        chain.doFilter(req, res);
    }
}
