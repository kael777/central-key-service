package com.example.keyserver;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/** 與 Go 版一致的資料模型。 */
public final class Model {

    private Model() {
    }

    public static class SystemRec {
        public String code;
        public String name;
        public List<String> ipAllow = new ArrayList<>();
        public String status = "enabled";
        public String mode = "required";
        public String note = "";
        public Instant createdAt = Instant.now();
    }

    public static class KeyVersion {
        public String kid;
        public String code;
        public int seq;
        public String alg = "ECIES-P256-AES256GCM";
        public byte[] spki;
        public byte[] wrapped;
        public String state; // pending / active / decrypt_only / retired
        public Instant notBefore = Instant.now();
        public Instant decryptUntil;
        public Instant createdAt = Instant.now();
    }

    public static class Audit {
        public Instant ts = Instant.now();
        public String actor;
        public String action;
        public String system;
        public String kid;
        public String ip;
        public String result;
    }
}
