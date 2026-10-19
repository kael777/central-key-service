import java.nio.charset.StandardCharsets;

import keysdk.KeyClient;
import keysdk.KeyError;

/** 端到端驗證：A 加密 → B 解密，走真實 mTLS 與中央服務。 */
public final class ClientSmoke {

    public static void main(String[] args) throws Exception {
        String base = args.length > 0 ? args[0] : "https://127.0.0.1:8443";
        String certs = args.length > 1 ? args[1] : "../../go-key-sdk/certs";

        KeyClient a = KeyClient.config()
                .baseUrl(base)
                .systemCode("SYS-A")
                .cert(certs + "/clients/SYS-A.crt", certs + "/clients/SYS-A.key")
                .ca(certs + "/ca.crt")
                .build();

        KeyClient b = KeyClient.config()
                .baseUrl(base)
                .systemCode("SYS-B")
                .cert(certs + "/clients/SYS-B.crt", certs + "/clients/SYS-B.key")
                .ca(certs + "/ca.crt")
                .build();

        String payload = "訂單編號=A123456&金額=1000";
        String token = a.encrypt("SYS-B", "urlparam", payload.getBytes(StandardCharsets.UTF_8));
        System.out.println("A encrypt → " + token.substring(0, 24) + "...（" + token.length() + " 字元）");

        byte[] plain = b.decrypt(token, "urlparam");
        String back = new String(plain, StandardCharsets.UTF_8);
        System.out.println("B decrypt → \"" + back + "\"");

        if (!back.equals(payload)) {
            throw new IllegalStateException("明文不符");
        }

        b.refresh();
        // purpose 不一致必須失敗
        try {
            b.decrypt(token, "body");
            throw new IllegalStateException("purpose 不符應該失敗");
        } catch (KeyError e) {
            if (!KeyError.AUTH.equals(e.code())) {
                throw new IllegalStateException("預期 ERR_AUTH，實際 " + e.code());
            }
        }

        System.out.println("snapshot A: mode=" + a.snapshot().mode + " peers=" + a.snapshot().peers.size());
        System.out.println("snapshot B: decrypt_versions=" + b.snapshot().decryptKids.size());
        System.out.println("PASS  Java Client 端到端成功");
    }
}
