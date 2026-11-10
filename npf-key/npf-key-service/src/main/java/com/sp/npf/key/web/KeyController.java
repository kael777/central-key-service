package com.sp.npf.key.web;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import com.sp.npf.key.service.KeyService;
import com.sp.npf.key.service.KeyService.FetchResult;

@RestController
public class KeyController {

    private final KeyService service;

    public KeyController(KeyService service) {
        this.service = service;
    }

    @GetMapping("/keys")
    public ResponseEntity<Map<String, Object>> batch(
            @RequestHeader(value = "X-Client-Id", required = false) String clientId,
            @RequestHeader(value = "X-Key-Etag", required = false) String etag,
            HttpServletRequest request) {
        return respond(service.fetch(clientId, request.getRemoteAddr(), null, etag));
    }

    @GetMapping("/keys/{keyName}")
    public ResponseEntity<Map<String, Object>> single(
            @PathVariable String keyName,
            @RequestHeader(value = "X-Client-Id", required = false) String clientId,
            @RequestHeader(value = "X-Key-Etag", required = false) String etag,
            HttpServletRequest request) {
        return respond(service.fetch(clientId, request.getRemoteAddr(), keyName, etag));
    }

    private ResponseEntity<Map<String, Object>> respond(FetchResult result) {
        if (result.notModified) {
            return ResponseEntity.status(HttpStatus.NOT_MODIFIED)
                    .eTag(result.etag)
                    .build();
        }
        return ResponseEntity.ok().eTag(result.etag).body(result.body);
    }
}
