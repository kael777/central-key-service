import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import keysdk.Json;
import keysdk.KeyCrypto;
import keysdk.KeyError;

/** 以 vectors.json 驗證 Java SDK：解密、密文重現、負向錯誤碼。 */
public final class VectorTest {

    private static int pass;
    private static int fail;

    public static void main(String[] args) throws Exception {
        String path = args.length > 0 ? args[0] : "../../key-protocol-vectors/v1/vectors.json";
        if (System.getenv("KEY_VECTORS") != null) {
            path = System.getenv("KEY_VECTORS");
        }
        String text = Files.readString(Path.of(path), StandardCharsets.UTF_8);
        Map<String, Object> doc = Json.obj(Json.parse(text));

        Map<String, PrivateKey> keys = new HashMap<>();
        Map<String, byte[]> spkis = new HashMap<>();
        for (Object o : Json.list(doc.get("keys"))) {
            Map<String, Object> k = Json.obj(o);
            String kid = Json.str(k.get("kid"));
            byte[] d = hex(Json.str(k.get("d_hex")));
            PrivateKey priv = KeyCrypto.privateKeyFromScalar(d);
            byte[] spki = KeyCrypto.publicKeyFromScalar(d).getEncoded();
            String expect = Json.str(k.get("spki_b64"));
            if (!Base64.getEncoder().encodeToString(spki).equals(expect)) {
                throw new IllegalStateException("SPKI 不符：" + kid);
            }
            keys.put(kid, priv);
            spkis.put(kid, spki);
        }

        System.out.println("[正向：解密]");
        for (Object o : Json.list(doc.get("positive"))) {
            Map<String, Object> v = Json.obj(o);
            check(Json.str(v.get("name")), () -> {
                byte[] pt = KeyCrypto.decrypt(keys.get(Json.str(v.get("kid"))),
                        Json.str(v.get("token")), Json.str(v.get("purpose")));
                if (!Base64.getEncoder().encodeToString(pt).equals(Json.str(v.get("plaintext_b64")))) {
                    throw new IllegalStateException("明文不一致");
                }
            });
        }

        System.out.println("\n[正向：固定隨機值重現密文]");
        for (Object o : Json.list(doc.get("positive"))) {
            Map<String, Object> v = Json.obj(o);
            check(Json.str(v.get("name")), () -> {
                String token = KeyCrypto.encryptWith(
                        spkis.get(Json.str(v.get("kid"))),
                        Json.str(v.get("kid")),
                        Json.str(v.get("purpose")),
                        Base64.getDecoder().decode(Json.str(v.get("plaintext_b64"))),
                        hex(Json.str(v.get("eph_d_hex"))),
                        hex(Json.str(v.get("iv_hex"))));
                if (!token.equals(Json.str(v.get("token")))) {
                    throw new IllegalStateException("密文與向量不符");
                }
            });
        }

        System.out.println("\n[負向：必須回傳指定錯誤碼]");
        for (Object o : Json.list(doc.get("negative"))) {
            Map<String, Object> n = Json.obj(o);
            check(Json.str(n.get("name")), () -> {
                String kid = Json.str(n.get("kid"));
                String expect = Json.str(n.get("expect_error"));
                if (!keys.containsKey(kid)) {
                    if (!expect.equals(KeyError.UNKNOWN_KID)) {
                        throw new IllegalStateException("預期 " + expect);
                    }
                    return;
                }
                try {
                    KeyCrypto.decrypt(keys.get(kid), Json.str(n.get("token")), Json.str(n.get("purpose")));
                } catch (KeyError e) {
                    if (!e.code().equals(expect)) {
                        throw new IllegalStateException("預期 " + expect + "，實際 " + e.code());
                    }
                    return;
                }
                throw new IllegalStateException("預期錯誤但解密成功");
            });
        }

        System.out.println("\n[邊界：超長 token]");
        check("oversize", () -> {
            try {
                KeyCrypto.parse("KEY1.SYS-B:3." + "A".repeat(9000));
            } catch (KeyError e) {
                if (e.code().equals(KeyError.FORMAT)) {
                    return;
                }
                throw new IllegalStateException("預期 FORMAT，實際 " + e.code());
            }
            throw new IllegalStateException("應拒絕");
        });

        System.out.println("\n結果：PASS " + pass + " / FAIL " + fail);
        System.exit(fail == 0 ? 0 : 1);
    }

    private static void check(String name, Runnable r) {
        try {
            r.run();
            pass++;
            System.out.println("  PASS  " + name);
        } catch (Throwable t) {
            fail++;
            System.out.println("  FAIL  " + name + "  → " + t.getMessage());
        }
    }

    private static byte[] hex(String s) {
        int n = s.length();
        byte[] out = new byte[n / 2];
        for (int i = 0; i < n; i += 2) {
            out[i / 2] = (byte) Integer.parseInt(s.substring(i, i + 2), 16);
        }
        return out;
    }

    private static ECPublicKey unused() {
        return null;
    }
}
