package com.sp.npf.key.web;

import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.sp.npf.key.service.KeyService;

@RestController
public class HealthController {

    private final KeyService service;

    public HealthController(KeyService service) {
        this.service = service;
    }

    @GetMapping("/health")
    public Map<String, Object> health() {
        return service.health();
    }
}
