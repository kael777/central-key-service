package com.example.keyserver;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

@RestController
public class AuthController {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String OIDC_COOKIE = "cms_oidc";
    private static final String SESSION_COOKIE = "cms_session";

    private final Oidc oidc;
    private final AppConfig cfg;

    public AuthController(Oidc oidc, AppConfig cfg) {
        this.oidc = oidc;
        this.cfg = cfg;
    }

    @GetMapping("/auth/login")
    public ResponseEntity<String> login() {
        if (!oidc.enabled()) {
            return ResponseEntity.status(404).body("未啟用 OIDC（app.oidc.issuer 為空）");
        }
        try {
            String state = random();
            String nonce = random();
            String verifier = random();
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("state", state);
            payload.put("nonce", nonce);
            payload.put("verifier", verifier);
            payload.put("exp", System.currentTimeMillis() / 1000 + 600);
            String cookie = Session.sign(cfg.csrfSecret(), payload);
            String url = oidc.authorizeUrl(state, nonce, verifier);
            return ResponseEntity.status(302)
                    .header(HttpHeaders.LOCATION, url)
                    .header(HttpHeaders.SET_COOKIE, cookie(OIDC_COOKIE, cookie, 600).toString())
                    .build();
        } catch (Exception e) {
            return ResponseEntity.status(502).body("OIDC 初始化失敗：" + e.getMessage());
        }
    }

    @GetMapping("/auth/callback")
    public ResponseEntity<String> callback(@RequestParam(required = false) String code,
                                           @RequestParam(required = false) String state,
                                           @RequestParam(required = false) String error,
                                           HttpServletRequest req) {
        if (!oidc.enabled()) {
            return ResponseEntity.status(404).body("未啟用 OIDC");
        }
        if (error != null) {
            return ResponseEntity.status(401).body("IdP 回傳錯誤：" + error);
        }
        if (code == null || state == null) {
            return ResponseEntity.status(400).body("缺少 code 或 state");
        }
        Map<String, Object> pending = Session.verify(cfg.csrfSecret(), readCookie(req, OIDC_COOKIE));
        if (pending == null || !state.equals(pending.get("state"))) {
            return ResponseEntity.status(400).body("state 不符或已過期");
        }
        try {
            String idToken = oidc.exchangeCode(code, String.valueOf(pending.get("verifier")));
            Map<String, Object> claims = oidc.verifyIdToken(idToken, String.valueOf(pending.get("nonce")));
            Role role = oidc.roleFor(claims);
            Map<String, Object> session = new LinkedHashMap<>();
            session.put("sub", String.valueOf(claims.getOrDefault("preferred_username", claims.get("sub"))));
            session.put("role", role.name());
            session.put("exp", System.currentTimeMillis() / 1000 + 8 * 3600);
            String cookie = Session.sign(cfg.csrfSecret(), session);
            return ResponseEntity.status(302)
                    .header(HttpHeaders.LOCATION, "/admin")
                    .header(HttpHeaders.SET_COOKIE, cookie(SESSION_COOKIE, cookie, 8 * 3600).toString())
                    .header(HttpHeaders.SET_COOKIE, cookie(OIDC_COOKIE, "", 0).toString())
                    .build();
        } catch (Exception e) {
            return ResponseEntity.status(401).body("登入失敗：" + e.getMessage());
        }
    }

    @GetMapping("/auth/logout")
    public ResponseEntity<String> logout() {
        return ResponseEntity.status(302)
                .header(HttpHeaders.LOCATION, "/admin")
                .header(HttpHeaders.SET_COOKIE, cookie(SESSION_COOKIE, "", 0).toString())
                .build();
    }

    /** 給頁面用：從 session cookie 取角色。 */
    public static Role sessionRole(AppConfig cfg, HttpServletRequest req) {
        Map<String, Object> payload = Session.verify(cfg.csrfSecret(), readCookie(req, SESSION_COOKIE));
        if (payload == null) {
            return null;
        }
        return Role.parse(String.valueOf(payload.get("role")), null);
    }

    private static String readCookie(HttpServletRequest req, String name) {
        Cookie[] cookies = req.getCookies();
        if (cookies == null) {
            return null;
        }
        for (Cookie c : cookies) {
            if (name.equals(c.getName())) {
                return c.getValue();
            }
        }
        return null;
    }

    private static ResponseCookie cookie(String name, String value, int maxAge) {
        return ResponseCookie.from(name, value)
                .httpOnly(true)
                .secure(true)
                .sameSite("Lax")
                .path("/")
                .maxAge(Duration.ofSeconds(maxAge))
                .build();
    }

    private static String random() {
        byte[] b = new byte[32];
        RANDOM.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }
}
