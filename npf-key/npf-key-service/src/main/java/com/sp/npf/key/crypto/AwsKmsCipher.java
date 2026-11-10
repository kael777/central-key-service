package com.sp.npf.key.crypto;

import java.nio.charset.StandardCharsets;
import java.util.Collections;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import com.sp.npf.key.config.NpfProperties;

import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.EncryptRequest;

/**
 * 正式環境：直接用 KMS Encrypt/Decrypt，主鑰不離開 KMS。
 * EncryptionContext 綁定 keyName，密文調包到別的鑰名會解不開。
 */
@Component
@ConditionalOnProperty(name = "npf.kms.mode", havingValue = "aws")
public class AwsKmsCipher implements KmsCipher {

    private final KmsClient kms;
    private final String keyArn;

    public AwsKmsCipher(NpfProperties props) {
        this.kms = KmsClient.create();
        this.keyArn = props.getKms().getKeyArn();
        if (keyArn == null || keyArn.isEmpty()) {
            throw new IllegalStateException("npf.kms.key-arn 未設定");
        }
    }

    @Override
    public byte[] encrypt(String keyName, byte[] plain) {
        return kms.encrypt(EncryptRequest.builder()
                .keyId(keyArn)
                .plaintext(SdkBytes.fromByteArray(plain))
                .encryptionContext(Collections.singletonMap("keyName", keyName))
                .build()).ciphertextBlob().asByteArray();
    }

    @Override
    public byte[] decrypt(String keyName, byte[] cipherText) {
        return kms.decrypt(DecryptRequest.builder()
                .keyId(keyArn)
                .ciphertextBlob(SdkBytes.fromByteArray(cipherText))
                .encryptionContext(Collections.singletonMap("keyName", keyName))
                .build()).plaintext().asByteArray();
    }

    @Override
    public String describe() {
        return "aws-kms:" + keyArn;
    }

    static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }
}
