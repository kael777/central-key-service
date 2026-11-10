package com.sp.npf.key.config;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class ClientRegistry {

    private static final Logger log = LoggerFactory.getLogger(ClientRegistry.class);

    private final Map<String, NpfProperties.Client> byIp = new HashMap<>();
    private final Map<String, NpfProperties.Client> byId = new HashMap<>();

    public ClientRegistry(NpfProperties props) {
        for (NpfProperties.Client c : props.getClients()) {
            log.info("[key-service] client id={} ips={} keys={}", c.getId(), c.getIps(), c.getAllowedKeys());
            byId.put(c.getId(), c);
            for (String ip : c.getIps()) {
                NpfProperties.Client prev = byIp.put(normalize(ip), c);
                if (prev != null && !prev.getId().equals(c.getId())) {
                    throw new IllegalStateException("IP " + ip + " 重複登記給 " + prev.getId() + " 與 " + c.getId());
                }
            }
        }
    }

    public NpfProperties.Client resolve(String remoteIp) {
        return byIp.get(normalize(remoteIp));
    }

    public NpfProperties.Client byId(String id) {
        return byId.get(id);
    }

    public static String normalize(String ip) {
        if (ip == null) {
            return "";
        }
        String s = ip.trim();
        if (s.startsWith("::ffff:")) {
            s = s.substring(7);
        }
        int pct = s.indexOf('%');
        if (pct >= 0) {
            s = s.substring(0, pct);
        }
        return s.toLowerCase(Locale.ROOT);
    }
}
