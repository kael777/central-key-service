package com.sp.npf.key.crypto;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import com.sp.npf.key.config.NpfProperties;

/**
 * 開發／測試用的本地 KMS：以 SHA-256(localKey) 作為 AES-256-GCM 金鑰。
 * 正式環境請把 npf.kms.mode 設為 aws。
 */
@Component
@ConditionalOnProperty(name = "npf.kms.mode", havingValue = "local", matchIfMissing = true)
public class LocalKmsCipher implements KmsCipher {

    private static final SecureRandom RANDOM = new SecureRandom();
    private final SecretKeySpec key;

    public LocalKmsCipher(NpfProperties props) {
        String seed = props.getKms().getLocalKey();
        if (seed == null || seed.isEmpty()) {
            seed = System.getenv("NPF_LOCAL_KMS_KEY");
        }
        if (seed == null || seed.isEmpty()) {
            seed = "npf-key-service-local-dev-only";
        }
        this.key = new SecretKeySpec(sha256(seed.getBytes(StandardCharsets.UTF_8)), "AES");
    }

    @Override
    public byte[] encrypt(String keyName, byte[] plain) {
        try {
            byte[] nonce = new byte[12];
            RANDOM.nextBytes(nonce);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
            cipher.updateAAD(keyName.getBytes(StandardCharsets.UTF_8));
            byte[] ct = cipher.doFinal(plain);
            byte[] out = new byte[nonce.length + ct.length];
            System.arraycopy(nonce, 0, out, 0, nonce.length);
            System.arraycopy(ct, 0, out, nonce.length, ct.length);
            return out;
        } catch (Exception e) {
            throw new IllegalStateException("local kms encrypt failed", e);
        }
    }

    @Override
    public byte[] decrypt(String keyName, byte[] cipherText) {
        try {
            byte[] nonce = new byte[12];
            System.arraycopy(cipherText, 0, nonce, 0, 12);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, nonce));
            cipher.updateAAD(keyName.getBytes(StandardCharsets.UTF_8));
            return cipher.doFinal(cipherText, 12, cipherText.length - 12);
        } catch (Exception e) {
            throw new IllegalStateException("local kms decrypt failed", e);
        }
    }

    @Override
    public String describe() {
        return "local-aes-gcm";
    }

    private static byte[] sha256(byte[] in) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(in);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static String b64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }
}
