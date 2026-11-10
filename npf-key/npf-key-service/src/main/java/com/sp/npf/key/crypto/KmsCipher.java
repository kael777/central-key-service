package com.sp.npf.key.crypto;

/** 金鑰本體的加解密（正式環境為 AWS KMS）。 */
public interface KmsCipher {

    byte[] encrypt(String keyName, byte[] plain);

    byte[] decrypt(String keyName, byte[] cipherText);

    String describe();
}
