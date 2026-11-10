package com.sp.npf.key.web;

import java.util.LinkedHashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import com.sp.npf.key.service.ApiException;

@RestControllerAdvice
public class ApiErrorHandler {

    private static final Logger log = LoggerFactory.getLogger(ApiErrorHandler.class);

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<Map<String, Object>> handle(ApiException e) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", e.getMessage());
        return ResponseEntity.status(e.getStatus()).body(body);
    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<Map<String, Object>> handleMissing(MissingServletRequestParameterException e) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "missing parameter: " + e.getParameterName());
        return ResponseEntity.status(400).body(body);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleAny(Exception e) {
        log.error("[key-service] request failed", e);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "internal error");
        return ResponseEntity.status(500).body(body);
    }
}
