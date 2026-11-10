package com.sp.npf.key;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.annotation.DirtiesContext;

import com.sp.npf.key.service.ApiException;
import com.sp.npf.key.service.KeyService;
import com.sp.npf.key.store.KeyRepository;
import com.sp.npf.key.store.KeyRepository.KeyRow;

@SpringBootTest
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class KeyLifecycleTest {

    @Autowired
    private KeyService service;
    @Autowired
    private KeyRepository repo;
    @Autowired
    private JdbcTemplate jdbc;

    @Test
    void importRotatesCurrentToPreviousAndRetiresOldest() {
        service.importPartner("game.ag.key", "v1".getBytes(), "AG", "first", "127.0.0.1");
        service.importPartner("game.ag.key", "v2".getBytes(), "AG", "second", "127.0.0.1");
        service.importPartner("game.ag.key", "v3".getBytes(), "AG", "third", "127.0.0.1");

        List<String> statuses = statuses("game.ag.key");
        assertEquals(1, statuses.stream().filter("CURRENT"::equals).count());
        assertEquals(1, statuses.stream().filter("PREVIOUS"::equals).count());
        assertEquals(1, statuses.stream().filter("RETIRED"::equals).count());
    }

    @Test
    void scheduledRotationSkipsWithinMinInterval() {
        service.rotate("relay.callback", true, "test", "127.0.0.1");
        service.scheduledRotate();
        Integer skipped = jdbc.queryForObject(
                "SELECT COUNT(*) FROM KEY_AUDIT_LOG WHERE ACTION = 'ROTATE_SKIPPED' AND KEY_NAME = 'relay.callback'",
                Integer.class);
        assertTrue(skipped != null && skipped >= 1);
    }

    @Test
    void concurrentRotationOnlyOneWins() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(2);
        List<Callable<Boolean>> tasks = new ArrayList<>();
        for (int i = 0; i < 2; i++) {
            tasks.add(() -> {
                try {
                    service.rotate("relay.daifu.sign", false, "race", "127.0.0.1");
                    return Boolean.TRUE;
                } catch (ApiException e) {
                    return Boolean.FALSE;
                }
            });
        }
        List<Future<Boolean>> results = pool.invokeAll(tasks);
        pool.shutdown();
        int success = 0;
        for (Future<Boolean> f : results) {
            if (f.get()) {
                success++;
            }
        }
        assertEquals(1, success, "兩個併發輪替應只有一個成功");
        assertEquals(1, jdbc.queryForObject(
                "SELECT COUNT(*) FROM KEY_SECRET WHERE KEY_NAME='relay.daifu.sign' AND STATUS='CURRENT'", Integer.class));
    }

    private List<String> statuses(String keyName) {
        List<String> out = new ArrayList<>();
        for (KeyRow row : repo.listByName(keyName)) {
            out.add(row.status);
        }
        return out;
    }
}
