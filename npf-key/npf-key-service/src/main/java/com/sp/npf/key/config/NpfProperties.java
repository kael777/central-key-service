package com.sp.npf.key.config;

import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "npf")
public class NpfProperties {

    private Keys keys = new Keys();
    private List<Client> clients = new ArrayList<>();
    private Kms kms = new Kms();
    private Rotate rotate = new Rotate();
    private int refreshSeconds = 3600;
    private int auditRetentionDays = 180;

    public Keys getKeys() {
        return keys;
    }

    public void setKeys(Keys keys) {
        this.keys = keys;
    }

    public List<Client> getClients() {
        return clients;
    }

    public void setClients(List<Client> clients) {
        this.clients = clients;
    }

    public Kms getKms() {
        return kms;
    }

    public void setKms(Kms kms) {
        this.kms = kms;
    }

    public Rotate getRotate() {
        return rotate;
    }

    public void setRotate(Rotate rotate) {
        this.rotate = rotate;
    }

    public int getAuditRetentionDays() {
        return auditRetentionDays;
    }

    public void setAuditRetentionDays(int auditRetentionDays) {
        this.auditRetentionDays = auditRetentionDays;
    }

    public int getRefreshSeconds() {
        return refreshSeconds;
    }

    public void setRefreshSeconds(int refreshSeconds) {
        this.refreshSeconds = refreshSeconds;
    }

    public static class Keys {
        private List<Hmac> hmac = new ArrayList<>();

        public List<Hmac> getHmac() {
            return hmac;
        }

        public void setHmac(List<Hmac> hmac) {
            this.hmac = hmac;
        }
    }

    public static class Hmac {
        private String name;
        private String remark = "";

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getRemark() {
            return remark;
        }

        public void setRemark(String remark) {
            this.remark = remark;
        }
    }

    public static class Client {
        private String id;
        private List<String> ips = new ArrayList<>();
        private List<String> allowedKeys = new ArrayList<>();

        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }

        public List<String> getIps() {
            return ips;
        }

        public void setIps(List<String> ips) {
            this.ips = ips;
        }

        public List<String> getAllowedKeys() {
            return allowedKeys;
        }

        public void setAllowedKeys(List<String> allowedKeys) {
            this.allowedKeys = allowedKeys;
        }
    }

    public static class Kms {
        private String mode = "local";
        private String keyArn = "";
        private String localKey = "";
        private String endpoint = "";

        public String getMode() {
            return mode;
        }

        public void setMode(String mode) {
            this.mode = mode;
        }

        public String getKeyArn() {
            return keyArn;
        }

        public void setKeyArn(String keyArn) {
            this.keyArn = keyArn;
        }

        public String getLocalKey() {
            return localKey;
        }

        public void setLocalKey(String localKey) {
            this.localKey = localKey;
        }

        public String getEndpoint() {
            return endpoint;
        }

        public void setEndpoint(String endpoint) {
            this.endpoint = endpoint;
        }
    }

    public static class Rotate {
        private String cron = "0 0 10 * * *";
        private String zone = "Asia/Shanghai";
        private int minIntervalHours = 4;

        public String getCron() {
            return cron;
        }

        public void setCron(String cron) {
            this.cron = cron;
        }

        public String getZone() {
            return zone;
        }

        public void setZone(String zone) {
            this.zone = zone;
        }

        public int getMinIntervalHours() {
            return minIntervalHours;
        }

        public void setMinIntervalHours(int minIntervalHours) {
            this.minIntervalHours = minIntervalHours;
        }
    }
}
