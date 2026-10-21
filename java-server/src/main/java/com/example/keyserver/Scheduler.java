package com.example.keyserver;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;

@Component
public class Scheduler {

    private static final Logger log = LoggerFactory.getLogger(Scheduler.class);

    private final KeyService svc;

    public Scheduler(KeyService svc) {
        this.svc = svc;
    }

    /** 每秒推進版本狀態（pending→active、緩衝期到期→retired）。 */
    @Scheduled(fixedDelay = 1000)
    public void tick() {
        try {
            svc.tick(Instant.now());
        } catch (Exception e) {
            log.warn("tick 失敗：{}", e.getMessage());
        }
    }

    /** 每分鐘檢查是否該排程輪替。 */
    @Scheduled(fixedDelay = 60_000, initialDelay = 60_000)
    public void autoRotate() {
        try {
            int n = svc.autoRotate(Instant.now());
            if (n > 0) {
                log.info("排程輪替 {} 個系統", n);
            }
        } catch (Exception e) {
            log.warn("自動輪替失敗：{}", e.getMessage());
        }
    }
}
