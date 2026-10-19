package keysdk;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * cms-key 協定 v1：純函式層（無網路）。
 *
 * <p>密文格式：{@code KEY1.{kid}.{base64url(0x01 | eph_spki_der(91) | iv(12) | ciphertext | tag(16))}}
 */
public final class KeyCrypto {

    public static final String PREFIX = "KEY1.";
    public static final int SPKI_LEN = 91;
    public static final int IV_LEN = 12;
    public static final int TAG_LEN = 16;
    public static final int KEY_LEN = 32;
    public static final int MAX_TOKEN_LEN = 8192;

    private static final SecureRandom RANDOM = new SecureRandom();

    private KeyCrypto() {
    }

    public static boolean validKid(String kid) {
        return kid != null && kid.matches("[A-Za-z0-9_:-]{1,64}");
    }

    public static boolean validPurpose(String purpose) {
        return purpose != null && purpose.matches("[a-z0-9_-]{1,32}");
    }

    /** 結構解析，不接觸金鑰。 */
    public static Token parse(String token) {
        if (token == null || token.length() > MAX_TOKEN_LEN) {
            throw new KeyError(KeyError.FORMAT, "token 為空或過長");
        }
        if (!token.startsWith(PREFIX)) {
            throw new KeyError(KeyError.FORMAT, "缺少前綴");
        }
        String rest = token.substring(PREFIX.length());
        int i = rest.indexOf('.');
        if (i <= 0) {
            throw new KeyError(KeyError.FORMAT, "kid 分隔錯誤");
        }
        String kid = rest.substring(0, i);
        String body = rest.substring(i + 1);
        if (!validKid(kid)) {
            throw new KeyError(KeyError.FORMAT, "kid 非法");
        }
        if (!body.matches("[A-Za-z0-9_-]+")) {
            throw new KeyError(KeyError.FORMAT, "payload 含非法字元");
        }
        byte[] payload;
        try {
            payload = Base64.getUrlDecoder().decode(body);
        } catch (IllegalArgumentException e) {
            throw new KeyError(KeyError.FORMAT, "payload 解碼失敗");
        }
        if (payload.length < 1 + SPKI_LEN + IV_LEN + TAG_LEN) {
            throw new KeyError(KeyError.FORMAT, "payload 過短");
        }
        if ((payload[0] & 0xff) != 1) {
            throw new KeyError(KeyError.FORMAT, "未知版本位元組");
        }
        byte[] spki = slice(payload, 1, 1 + SPKI_LEN);
        byte[] iv = slice(payload, 1 + SPKI_LEN, 1 + SPKI_LEN + IV_LEN);
        byte[] ct = slice(payload, 1 + SPKI_LEN + IV_LEN, payload.length);
        return new Token(kid, spki, iv, ct);
    }

    /** 加密（隨機臨時金鑰與 IV）。 */
    public static String encrypt(byte[] spkiDer, String kid, String purpose, byte[] plaintext) {
        return encryptWith(spkiDer, kid, purpose, plaintext, null, null);
    }

    /** 加密；ephScalar／iv 供測試注入固定隨機值，生產環境傳 null。 */
    public static String encryptWith(byte[] spkiDer, String kid, String purpose, byte[] plaintext,
                                     byte[] ephScalar, byte[] iv) {
        if (!validKid(kid)) {
            throw new KeyError(KeyError.FORMAT, "kid 非法");
        }
        if (!validPurpose(purpose)) {
            throw new KeyError(KeyError.FORMAT, "purpose 非法");
        }
        ECPublicKey recipient = publicKeyFromSpki(spkiDer);

        PrivateKey ephPriv;
        byte[] ephSpki;
        if (ephScalar != null) {
            ephPriv = privateKeyFromScalar(ephScalar);
            ephSpki = publicKeyFromScalar(ephScalar).getEncoded();
        } else {
            KeyPair kp = generate();
            ephPriv = kp.getPrivate();
            ephSpki = kp.getPublic().getEncoded();
        }
        if (ephSpki.length != SPKI_LEN) {
            throw new KeyError(KeyError.KEY, "臨時公鑰長度異常：" + ephSpki.length);
        }

        if (iv == null) {
            iv = new byte[IV_LEN];
            RANDOM.nextBytes(iv);
        } else if (iv.length != IV_LEN) {
            throw new KeyError(KeyError.FORMAT, "IV 需為 12 bytes");
        }

        byte[] shared = ecdh(ephPriv, recipient);
        byte[] key = deriveKey(shared, kid, purpose);
        byte[] sealed = gcm(Cipher.ENCRYPT_MODE, key, iv, aad(kid, purpose), plaintext);

        byte[] payload = new byte[1 + SPKI_LEN + IV_LEN + sealed.length];
        payload[0] = 1;
        System.arraycopy(ephSpki, 0, payload, 1, SPKI_LEN);
        System.arraycopy(iv, 0, payload, 1 + SPKI_LEN, IV_LEN);
        System.arraycopy(sealed, 0, payload, 1 + SPKI_LEN + IV_LEN, sealed.length);

        return PREFIX + kid + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(payload);
    }

    /** 解密；purpose 必須與加密時一致。 */
    public static byte[] decrypt(PrivateKey privateKey, String token, String purpose) {
        if (!validPurpose(purpose)) {
            throw new KeyError(KeyError.FORMAT, "purpose 非法");
        }
        Token t = parse(token);
        ECPublicKey ephPub = publicKeyFromSpki(t.ephemeralSpki);
        byte[] shared = ecdh(privateKey, ephPub);
        byte[] key = deriveKey(shared, t.kid, purpose);

        byte[] body = slice(t.ciphertext, 0, t.ciphertext.length - TAG_LEN);
        byte[] tag = slice(t.ciphertext, t.ciphertext.length - TAG_LEN, t.ciphertext.length);
        byte[] sealed = new byte[body.length + tag.length];
        System.arraycopy(body, 0, sealed, 0, body.length);
        System.arraycopy(tag, 0, sealed, body.length, tag.length);

        return gcm(Cipher.DECRYPT_MODE, key, t.iv, aad(t.kid, purpose), sealed);
    }

    /** 由 32 bytes 私鑰純量建立 PrivateKey。 */
    public static PrivateKey privateKeyFromScalar(byte[] d) {
        if (d == null || d.length != KEY_LEN) {
            throw new KeyError(KeyError.KEY, "私鑰需為 32 bytes");
        }
        try {
            ECPrivateKeySpec spec = new ECPrivateKeySpec(new BigInteger(1, d), p256());
            return KeyFactory.getInstance("EC").generatePrivate(spec);
        } catch (Exception e) {
            throw new KeyError(KeyError.KEY, "建立私鑰失敗", e);
        }
    }

    /** 由 32 bytes 私鑰純量算出公鑰（用於重現固定密文）。 */
    public static ECPublicKey publicKeyFromScalar(byte[] d) {
        try {
            ECParameterSpec spec = p256();
            ECPoint point = EcMath.multiply(new BigInteger(1, d), spec.getGenerator(), spec);
            return (ECPublicKey) KeyFactory.getInstance("EC")
                    .generatePublic(new ECPublicKeySpec(point, spec));
        } catch (KeyError e) {
            throw e;
        } catch (Exception e) {
            throw new KeyError(KeyError.KEY, "由純量計算公鑰失敗", e);
        }
    }

    /** 解析 SPKI 並限制為 P-256。 */
    public static ECPublicKey publicKeyFromSpki(byte[] der) {
        try {
            PublicKey key = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(der));
            ECPublicKey ec = (ECPublicKey) key;
            if (!sameParams(ec.getParams(), p256())) {
                throw new KeyError(KeyError.KEY, "曲線不是 P-256");
            }
            return ec;
        } catch (KeyError e) {
            throw e;
        } catch (Exception e) {
            throw new KeyError(KeyError.KEY, "SPKI 解析失敗", e);
        }
    }

    /** 去除 PEM 標頭並解 base64，回傳 DER。 */
    public static byte[] pemToDer(String pem) {
        String body = pem.replaceAll("-----[^-]+-----", "").replaceAll("\\s", "");
        return Base64.getDecoder().decode(body);
    }
    // ---------- 內部 ----------

    private static KeyPair generate() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            return kpg.generateKeyPair();
        } catch (Exception e) {
            throw new KeyError(KeyError.KEY, "產生金鑰失敗", e);
        }
    }

    private static ECParameterSpec p256() {
        try {
            AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
            ap.init(new ECGenParameterSpec("secp256r1"));
            return ap.getParameterSpec(ECParameterSpec.class);
        } catch (Exception e) {
            throw new KeyError(KeyError.KEY, "取得 P-256 參數失敗", e);
        }
    }

    private static boolean sameParams(ECParameterSpec a, ECParameterSpec b) {
        return a.getCurve().getField().equals(b.getCurve().getField())
                && a.getCurve().getA().equals(b.getCurve().getA())
                && a.getCurve().getB().equals(b.getCurve().getB())
                && a.getGenerator().equals(b.getGenerator())
                && a.getOrder().equals(b.getOrder())
                && a.getCofactor() == b.getCofactor();
    }

    private static byte[] ecdh(PrivateKey priv, PublicKey pub) {
        try {
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(priv);
            ka.doPhase(pub, true);
            return ka.generateSecret();
        } catch (Exception e) {
            throw new KeyError(KeyError.KEY, "ECDH 失敗", e);
        }
    }

    private static byte[] gcm(int mode, byte[] key, byte[] iv, byte[] aad, byte[] input) {
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
            c.updateAAD(aad);
            return c.doFinal(input);
        } catch (Exception e) {
            if (mode == Cipher.DECRYPT_MODE) {
                throw new KeyError(KeyError.AUTH, "GCM 認證失敗", e);
            }
            throw new KeyError(KeyError.KEY, "AES-GCM 失敗", e);
        }
    }

    /** RFC 5869 HKDF-SHA256，salt 為空（等價 32 bytes 零）。 */
    static byte[] deriveKey(byte[] shared, String kid, String purpose) {
        String info = "cms-key-v1|" + kid + "|" + purpose;
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(new byte[32], "HmacSHA256"));
            byte[] prk = mac.doFinal(shared);

            mac.init(new SecretKeySpec(prk, "HmacSHA256"));
            mac.update(info.getBytes(StandardCharsets.UTF_8));
            mac.update((byte) 0x01);
            return mac.doFinal(); // 32 bytes，等於 T(1)
        } catch (Exception e) {
            throw new KeyError(KeyError.KEY, "HKDF 導出失敗", e);
        }
    }

    private static byte[] aad(String kid, String purpose) {
        byte[] k = kid.getBytes(StandardCharsets.UTF_8);
        byte[] p = purpose.getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[k.length + 1 + p.length];
        System.arraycopy(k, 0, out, 0, k.length);
        out[k.length] = 0;
        System.arraycopy(p, 0, out, k.length + 1, p.length);
        return out;
    }

    private static byte[] slice(byte[] src, int from, int to) {
        byte[] out = new byte[to - from];
        System.arraycopy(src, from, out, 0, out.length);
        return out;
    }

    /** 供測試：計算 token 的 SHA-256 摘要長度檢查（無實際用途）。 */
    static int digestLen() {
        try {
            return MessageDigest.getInstance("SHA-256").getDigestLength();
        } catch (Exception e) {
            return 32;
        }
    }

    static boolean isEcPrivate(PrivateKey k) {
        return k instanceof ECPrivateKey;
    }
}
