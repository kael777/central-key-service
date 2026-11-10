package com.sp.npf.key.web;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.sp.npf.key.service.ApiException;
import com.sp.npf.key.service.KeyService;
import com.sp.npf.key.store.KeyRepository.KeyRow;

/** 管理接口：只接受 127.0.0.1（SSH 進主機後 curl localhost）。 */
@RestController
public class AdminController {

    private final KeyService service;

    public AdminController(KeyService service) {
        this.service = service;
    }

    @PostMapping("/admin/keys/{keyName}/rotate")
    public ResponseEntity<Map<String, Object>> rotate(@PathVariable String keyName,
                                                      @RequestParam(defaultValue = "false") boolean dropPrevious,
                                                      @RequestParam String reason,
                                                      HttpServletRequest request) {
        requireLocal(request);
        KeyRow row = service.rotate(keyName, dropPrevious, reason, request.getRemoteAddr());
        return ResponseEntity.ok(view(row));
    }

    @PostMapping("/admin/keys/{keyName}/import")
    public ResponseEntity<Map<String, Object>> importPartner(@PathVariable String keyName,
                                                             @RequestParam String value,
                                                             @RequestParam(required = false) String remark,
                                                             @RequestParam String reason,
                                                             HttpServletRequest request) {
        requireLocal(request);
        byte[] raw = value.startsWith("b64:") ? Base64.getDecoder().decode(value.substring(4))
                : value.getBytes(StandardCharsets.UTF_8);
        KeyRow row = service.importPartner(keyName, raw, remark, reason, request.getRemoteAddr());
        return ResponseEntity.ok(view(row));
    }

    private void requireLocal(HttpServletRequest request) {
        String ip = request.getRemoteAddr();
        if (!"127.0.0.1".equals(ip) && !"0:0:0:0:0:0:0:1".equals(ip) && !"::1".equals(ip)) {
            throw new ApiException(403, "only localhost");
        }
    }

    private Map<String, Object> view(KeyRow row) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("key", row.keyName);
        m.put("status", row.status);
        m.put("version", row.version);
        m.put("keyId", row.keyId);
        return m;
    }
}
