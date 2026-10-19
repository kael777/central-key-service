package keysdk;

/** 解析後的密文結構；ciphertext 已包含 16 bytes GCM tag。 */
public final class Token {
    public final String kid;
    public final byte[] ephemeralSpki;
    public final byte[] iv;
    public final byte[] ciphertext;

    Token(String kid, byte[] ephemeralSpki, byte[] iv, byte[] ciphertext) {
        this.kid = kid;
        this.ephemeralSpki = ephemeralSpki;
        this.iv = iv;
        this.ciphertext = ciphertext;
    }
}
