package com.example.keyserver;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
public class ApiController {

    private final KeyService svc;
    private final Identity identity;
    private final AppConfig cfg;

    public ApiController(KeyService svc, Identity identity, AppConfig cfg) {
        this.svc = svc;
        this.identity = identity;
        this.cfg = cfg;
    }

    @GetMapping("/healthz")
    public Map<String, Object> health() {
        return Map.of("status", "ok", "store", svc.storeInfo());
    }

    @GetMapping(value = "/metrics", produces = MediaType.TEXT_PLAIN_VALUE)
    public String metrics() {
        return svc.metrics();
    }

    // ---------- 系統 API ----------

    @GetMapping("/api/v1/sync")
    public Map<String, Object> sync(HttpServletRequest req) {
        String code = identity.requireSystem(req);
        return svc.sync(code, identity.clientIp(req));
    }

    @PostMapping("/api/v1/self/private-key")
    public Map<String, Object> privateKey(@RequestBody Map<String, Object> body, HttpServletRequest req) {
        String code = identity.requireSystem(req);
        Object kid = body.get("kid");
        if (kid == null || String.valueOf(kid).isBlank()) {
            throw new ApiException(400, "invalid_request", "缺少 kid");
        }
        return svc.privateKey(code, String.valueOf(kid), identity.clientIp(req));
    }

    // ---------- 角色 ----------

    private Role roleOf(String token) {
        if (token == null || token.isBlank()) {
            return null;
        }
        if (token.equals(cfg.adminToken)) {
            return Role.ADMIN;
        }
        if (!cfg.operatorToken.isBlank() && token.equals(cfg.operatorToken)) {
            return Role.OPERATOR;
        }
        if (!cfg.viewerToken.isBlank() && token.equals(cfg.viewerToken)) {
            return Role.VIEWER;
        }
        return null;
    }

    private Role requireRole(String token, Role min) {
        Role role = roleOf(token);
        if (role == null || !role.atLeast(min)) {
            throw new ApiException(403, "forbidden", "權限不足（需要 " + min.name().toLowerCase() + "）");
        }
        return role;
    }

    // ---------- 管理 API ----------

    @GetMapping("/api/v1/admin/systems")
    public List<Map<String, Object>> listSystems(@RequestHeader(value = "X-Admin-Token", required = false) String token) {
        requireRole(token, Role.VIEWER);
        return systemsView();
    }

    @PostMapping("/api/v1/admin/systems")
    public Map<String, Object> createSystem(@RequestHeader(value = "X-Admin-Token", required = false) String token,
                                            @RequestBody Map<String, Object> body) {
        requireRole(token, Role.ADMIN);
        Model.SystemRec s = svc.register(str(body.get("code")), str(body.get("name")),
                parseIps(body.get("ip_allow")), str(body.get("note")));
        return Map.of("code", s.code, "name", s.name, "ip_allow", s.ipAllow, "status", s.status);
    }

    @GetMapping("/api/v1/admin/systems/{code}/versions")
    public List<Map<String, Object>> versions(@RequestHeader(value = "X-Admin-Token", required = false) String token,
                                              @PathVariable String code) {
        requireRole(token, Role.VIEWER);
        svc.system(code);
        List<Map<String, Object>> out = new ArrayList<>();
        for (Model.KeyVersion v : svc.versionsOf(code)) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("kid", v.kid);
            m.put("state", v.state);
            m.put("not_before", v.notBefore.toString());
            m.put("decrypt_until", v.decryptUntil == null ? null : v.decryptUntil.toString());
            out.add(m);
        }
        return out;
    }

    @PostMapping("/api/v1/admin/systems/{code}/rotate")
    public Map<String, Object> rotate(@RequestHeader(value = "X-Admin-Token", required = false) String token,
                                      @PathVariable String code) {
        requireRole(token, Role.OPERATOR);
        Model.KeyVersion v = svc.rotate(code, "admin", "");
        return Map.of("kid", v.kid, "state", v.state, "not_before", v.notBefore.toString());
    }

    @PostMapping("/api/v1/admin/systems/{code}/schedule")
    public Map<String, Object> schedule(@RequestHeader(value = "X-Admin-Token", required = false) String token,
                                        @PathVariable String code) {
        requireRole(token, Role.OPERATOR);
        Model.KeyVersion v = svc.schedule(code, "admin", "");
        return Map.of("kid", v.kid, "state", v.state, "activate_at", v.notBefore.toString());
    }

    @PostMapping("/api/v1/admin/systems/{code}/{action}")
    public Map<String, Object> status(@RequestHeader(value = "X-Admin-Token", required = false) String token,
                                      @PathVariable String code, @PathVariable String action) {
        requireRole(token, Role.OPERATOR);
        String status = switch (action) {
            case "enable" -> "enabled";
            case "disable" -> "disabled";
            default -> throw new ApiException(400, "invalid_action", "不支援的操作：" + action);
        };
        Model.SystemRec s = svc.setStatus(code, status, "admin");
        return Map.of("code", s.code, "status", s.status);
    }

    @GetMapping("/api/v1/admin/audit")
    public List<Map<String, Object>> audit(@RequestHeader(value = "X-Admin-Token", required = false) String token,
                                           @RequestParam(defaultValue = "100") int limit) {
        requireRole(token, Role.VIEWER);
        List<Map<String, Object>> out = new ArrayList<>();
        for (Model.Audit a : svc.auditList(limit)) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("ts", a.ts.toString());
            m.put("actor", a.actor);
            m.put("action", a.action);
            m.put("system", a.system);
            m.put("kid", a.kid);
            m.put("ip", a.ip);
            m.put("result", a.result);
            out.add(m);
        }
        return out;
    }

    // ---------- 後台頁面 ----------

    @GetMapping(value = "/admin", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> adminPage(@RequestParam(value = "token", required = false) String token,
                                            HttpServletRequest req) {
        Role role = roleOf(token);
        if (role == null) {
            role = AuthController.sessionRole(cfg, req);
        }
        if (role == null) {
            return ResponseEntity.ok(loginPage());
        }
        String csrf = Csrf.issue(cfg.csrfSecret(), role);
        StringBuilder sb = new StringBuilder();
        sb.append("<!doctype html><html lang=\"zh-Hant\"><head><meta charset=\"utf-8\">")
                .append("<title>系統登記與授權管理</title><style>")
                .append("body{font-family:-apple-system,'Segoe UI',sans-serif;margin:32px;color:#111}")
                .append("table{border-collapse:collapse;margin:12px 0}th,td{border-bottom:1px solid #e5e7eb;padding:8px 12px;text-align:left;font-size:14px}")
                .append("th{background:#f8fafc}.tag{padding:1px 8px;border-radius:10px;background:#eef2ff;font-size:12px}")
                .append("form.inline{display:inline}fieldset{border:1px solid #e5e7eb;border-radius:8px;padding:16px;max-width:760px}")
                .append("input,button{font-size:14px;padding:6px 10px;margin:4px 6px 4px 0}")
                .append("</style></head><body>");
        sb.append("<h1>系統登記與授權管理</h1>");
        sb.append("<p>儲存後端：<code>").append(esc(svc.storeInfo())).append("</code>　角色：<span class=\"tag\">")
                .append(role.name().toLowerCase()).append("</span></p>");
        sb.append("<table><tr><th>系統代碼</th><th>名稱</th><th>允許 IP</th><th>狀態</th><th>現行版本</th><th>操作</th></tr>");
        if (svc.listSystems().isEmpty()) {
            sb.append("<tr><td colspan=\"6\">目前沒有任何系統，請用下方表單建立</td></tr>");
        }
        for (Map<String, Object> row : systemsView()) {
            String code = esc(str(row.get("code")));
            sb.append("<tr><td>").append(code).append("</td><td>").append(esc(str(row.get("name"))))
                    .append("</td><td>").append(esc(str(row.get("ip_allow"))))
                    .append("</td><td><span class=\"tag\">").append(esc(str(row.get("status"))))
                    .append("</span></td><td>").append(esc(str(row.get("active_kid"))))
                    .append("</td><td>");
            if (role.atLeast(Role.OPERATOR)) {
                sb.append(form(token, csrf, code, "rotate", "輪替"));
                sb.append(form(token, csrf, code, "schedule", "排程輪替"));
                if ("enabled".equals(str(row.get("status")))) {
                    sb.append(form(token, csrf, code, "disable", "停用"));
                } else {
                    sb.append(form(token, csrf, code, "enable", "啟用"));
                }
            } else {
                sb.append("—");
            }
            sb.append("</td></tr>");
        }
        sb.append("</table>");
        if (role.atLeast(Role.ADMIN)) {
            sb.append("<fieldset><legend>新增系統</legend><form method=\"post\" action=\"/admin/create\">")
                    .append("<input type=\"hidden\" name=\"token\" value=\"").append(esc(token)).append("\">")
                    .append("<input type=\"hidden\" name=\"csrf\" value=\"").append(esc(csrf)).append("\">")
                    .append("<input name=\"code\" placeholder=\"系統代碼（如 SYS-D）\" required>")
                    .append("<input name=\"name\" placeholder=\"系統名稱\">")
                    .append("<input name=\"ip_allow\" placeholder=\"允許 IP（空白分隔，可留空）\" size=\"30\">")
                    .append("<input name=\"note\" placeholder=\"備註（選填）\">")
                    .append("<button>建立並產生金鑰</button></form></fieldset>");
        }
        sb.append("<p><a href=\"/admin/audit?token=").append(esc(token)).append("\">檢視稽核</a></p>");
        sb.append("</body></html>");
        return ResponseEntity.ok(sb.toString());
    }

    @PostMapping(value = "/admin/action", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> adminAction(@RequestParam(required = false) String token, @RequestParam String csrf,
                                              @RequestParam String code, @RequestParam String action,
                                              HttpServletRequest req) {
        Role role = roleOf(token);
        if (role == null) {
            role = AuthController.sessionRole(cfg, req);
        }
        if (role == null || !role.atLeast(Role.OPERATOR)) {
            return ResponseEntity.status(403).body("權限不足");
        }
        if (!Csrf.verify(cfg.csrfSecret(), role, csrf)) {
            return ResponseEntity.status(403).body("CSRF 驗證失敗");
        }
        switch (action) {
            case "rotate" -> svc.rotate(code, role.name().toLowerCase(), "");
            case "schedule" -> svc.schedule(code, role.name().toLowerCase(), "");
            case "enable" -> svc.setStatus(code, "enabled", role.name().toLowerCase());
            case "disable" -> svc.setStatus(code, "disabled", role.name().toLowerCase());
            default -> throw new ApiException(400, "invalid_action", "不支援的操作：" + action);
        }
        return ResponseEntity.status(302).header("Location", token == null || token.isBlank() ? "/admin" : "/admin?token=" + token).build();
    }

    @PostMapping(value = "/admin/create", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> adminCreate(@RequestParam(required = false) String token, @RequestParam String csrf,
                                              @RequestParam String code,
                                              @RequestParam(required = false) String name,
                                              @RequestParam(required = false) String ip_allow,
                                              @RequestParam(required = false) String note,
                                              HttpServletRequest req) {
        Role role = roleOf(token);
        if (role == null) {
            role = AuthController.sessionRole(cfg, req);
        }
        if (role == null || !role.atLeast(Role.ADMIN)) {
            return ResponseEntity.status(403).body("權限不足");
        }
        if (!Csrf.verify(cfg.csrfSecret(), role, csrf)) {
            return ResponseEntity.status(403).body("CSRF 驗證失敗");
        }
        svc.register(code, name, parseIps(ip_allow), note);
        return ResponseEntity.status(302).header("Location", token == null || token.isBlank() ? "/admin" : "/admin?token=" + token).build();
    }

    @GetMapping(value = "/admin/audit", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> adminAudit(@RequestParam(value = "token", required = false) String token,
                                             HttpServletRequest req) {
        Role role = roleOf(token);
        if (role == null) {
            role = AuthController.sessionRole(cfg, req);
        }
        if (role == null) {
            return ResponseEntity.status(401).body("權杖錯誤");
        }
        StringBuilder sb = new StringBuilder("<!doctype html><html lang=\"zh-Hant\"><head><meta charset=\"utf-8\"><title>稽核</title></head><body>");
        sb.append("<h1>稽核記錄</h1><table><tr><th>時間</th><th>操作者</th><th>動作</th><th>系統</th><th>KID</th><th>IP</th><th>結果</th></tr>");
        for (Model.Audit a : svc.auditList(200)) {
            sb.append("<tr><td>").append(esc(a.ts.toString())).append("</td><td>").append(esc(a.actor))
                    .append("</td><td>").append(esc(a.action)).append("</td><td>").append(esc(a.system))
                    .append("</td><td>").append(esc(a.kid)).append("</td><td>").append(esc(a.ip))
                    .append("</td><td>").append(esc(a.result)).append("</td></tr>");
        }
        sb.append("</table></body></html>");
        return ResponseEntity.ok(sb.toString());
    }

    // ---------- 例外 ----------

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<Map<String, Object>> handle(ApiException e) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", e.getMessage());
        body.put("code", e.code());
        return ResponseEntity.status(e.status()).body(body);
    }

    @ExceptionHandler(org.springframework.web.bind.MissingServletRequestParameterException.class)
    public ResponseEntity<Map<String, Object>> handleMissing(Exception e) {
        return ResponseEntity.status(400).body(Map.of("error", "缺少必要參數"));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleAny(Exception e) {
        return ResponseEntity.status(500).body(Map.of("error", "internal: " + e.getMessage()));
    }

    // ---------- 工具 ----------

    private List<Map<String, Object>> systemsView() {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Model.SystemRec s : svc.listSystems()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("code", s.code);
            m.put("name", s.name);
            m.put("ip_allow", String.join(" ", s.ipAllow));
            m.put("status", s.status);
            m.put("active_kid", svc.activeKid(s.code));
            out.add(m);
        }
        return out;
    }

    private static List<String> parseIps(Object raw) {
        List<String> ips = new ArrayList<>();
        if (raw instanceof List<?> list) {
            for (Object o : list) {
                ips.add(String.valueOf(o));
            }
        } else if (raw instanceof String s && !s.isBlank()) {
            for (String p : s.split("[,\\s]+")) {
                if (!p.isBlank()) {
                    ips.add(p);
                }
            }
        }
        return ips;
    }

    private static String form(String token, String csrf, String code, String action, String label) {
        return "<form class=\"inline\" method=\"post\" action=\"/admin/action\">" +
                "<input type=\"hidden\" name=\"token\" value=\"" + esc(token) + "\">" +
                "<input type=\"hidden\" name=\"csrf\" value=\"" + esc(csrf) + "\">" +
                "<input type=\"hidden\" name=\"code\" value=\"" + esc(code) + "\">" +
                "<input type=\"hidden\" name=\"action\" value=\"" + action + "\">" +
                "<button>" + label + "</button></form> ";
    }

    private static String loginPage() {
        return "<!doctype html><html lang=\"zh-Hant\"><head><meta charset=\"utf-8\"><title>登入</title></head><body>" +
                "<h1>中央 KEY 管理服務</h1><form method=\"get\" action=\"/admin\">" +
                "<input name=\"token\" type=\"password\" placeholder=\"管理權杖\" required>" +
                "<button>登入</button></form>" +
                "<p><a href=\"/auth/login\">使用 SSO 登入</a></p></body></html>";
    }

    private static String str(Object o) {
        return o == null ? "" : String.valueOf(o);
    }

    private static String esc(String s) {
        return s == null ? "" : s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }
}
