package com.example.keyserver;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.util.Arrays;

/** 金鑰產生、SPKI 匯出、私鑰包裝。協定與 Go 版一致。 */
public final class Crypto {

    private static final SecureRandom RANDOM = new SecureRandom();

    private Crypto() {
    }

    public static ECParameterSpec p256() throws Exception {
        AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
        ap.init(new ECGenParameterSpec("secp256r1"));
        return ap.getParameterSpec(ECParameterSpec.class);
    }

    public static KeyPair generate() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        return kpg.generateKeyPair();
    }

    public static byte[] spki(PublicKey pub) {
        return pub.getEncoded(); // X.509 SubjectPublicKeyInfo, 91 bytes
    }

    public static byte[] scalar(PrivateKey priv) {
        byte[] s = ((ECPrivateKey) priv).getS().toByteArray();
        if (s.length == 32) {
            return s;
        }
        byte[] out = new byte[32];
        if (s.length > 32) {
            System.arraycopy(s, s.length - 32, out, 0, 32);
        } else {
            System.arraycopy(s, 0, out, 32 - s.length, s.length);
        }
        return out;
    }

    public static PrivateKey privateFromScalar(byte[] s) throws Exception {
        ECPrivateKeySpec spec = new ECPrivateKeySpec(new BigInteger(1, s), p256());
        return KeyFactory.getInstance("EC").generatePrivate(spec);
    }

    public static byte[] pkcs8(PrivateKey priv) {
        return priv.getEncoded();
    }

    /** 回傳 nonce(12) || ciphertext || tag(16)。 */
    public static byte[] wrap(byte[] kek, byte[] plain) throws Exception {
        byte[] nonce = new byte[12];
        RANDOM.nextBytes(nonce);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(kek, "AES"), new GCMParameterSpec(128, nonce));
        byte[] ct = c.doFinal(plain);
        byte[] out = new byte[nonce.length + ct.length];
        System.arraycopy(nonce, 0, out, 0, nonce.length);
        System.arraycopy(ct, 0, out, nonce.length, ct.length);
        return out;
    }

    public static byte[] unwrap(byte[] kek, byte[] wrapped) throws Exception {
        byte[] nonce = Arrays.copyOfRange(wrapped, 0, 12);
        byte[] ct = Arrays.copyOfRange(wrapped, 12, wrapped.length);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(kek, "AES"), new GCMParameterSpec(128, nonce));
        return c.doFinal(ct);
    }

    public static byte[] hexToBytes(String hex) {
        if (hex == null || hex.isBlank()) {
            return new byte[0];
        }
        int n = hex.length();
        byte[] out = new byte[n / 2];
        for (int i = 0; i < n; i += 2) {
            out[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        }
        return out;
    }
}
