// Package keycrypto 實作 cms-key 協定 v1 的純函式層：無網路、無全域狀態，
// 隨機來源可注入，供測試向量與業務程式共用。
//
// 密文格式：KEY1.{kid}.{base64url(0x01 | eph_spki_der(91) | iv(12) | ciphertext | tag(16))}
package keycrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"math/big"
)

// EncryptTo 以收方公鑰加密，臨時金鑰與 IV 皆取自 crypto/rand。
func EncryptTo(spki []byte, kid, purpose string, plaintext []byte) (string, error) {
	return EncryptToWith(spki, kid, purpose, plaintext, nil, nil)
}

// EncryptToWith 允許注入臨時私鑰純量與 IV，供測試向量重現固定密文使用。
// 兩者傳 nil 代表使用 crypto/rand；生產環境請一律傳 nil。
func EncryptToWith(spki []byte, kid, purpose string, plaintext, ephScalar, iv []byte) (string, error) {
	if !ValidKID(kid) {
		return "", newErr(ErrFormat, "kid 格式非法：%q", kid)
	}
	if !ValidPurpose(purpose) {
		return "", newErr(ErrFormat, "purpose 格式非法：%q", purpose)
	}
	recipient, err := PublicKeyFromSPKI(spki)
	if err != nil {
		return "", err
	}

	var eph *ecdh.PrivateKey
	if ephScalar == nil {
		eph, err = ecdh.P256().GenerateKey(rand.Reader)
	} else {
		if len(ephScalar) != KeyLen {
			return "", newErr(ErrKey, "臨時私鑰長度 %d，應為 32", len(ephScalar))
		}
		eph, err = ecdh.P256().NewPrivateKey(ephScalar)
	}
	if err != nil {
		return "", wrapErr(ErrKey, err, "建立臨時金鑰失敗")
	}

	shared, err := eph.ECDH(recipient)
	if err != nil {
		return "", wrapErr(ErrKey, err, "ECDH 失敗")
	}
	key, err := deriveKey(shared, kid, purpose)
	if err != nil {
		return "", err
	}
	aead, err := newGCM(key)
	if err != nil {
		return "", err
	}

	if iv == nil {
		iv = make([]byte, IVLen)
		if _, err := rand.Read(iv); err != nil {
			return "", wrapErr(ErrKey, err, "產生 IV 失敗")
		}
	} else if len(iv) != IVLen {
		return "", newErr(ErrFormat, "IV 長度 %d，應為 12", len(iv))
	}

	ct := aead.Seal(nil, iv, plaintext, aad(kid, purpose))

	ephSPKI, err := SPKIFromECDH(eph.PublicKey())
	if err != nil {
		return "", err
	}
	payload := make([]byte, 0, 1+SPKILen+IVLen+len(ct))
	payload = append(payload, VersionByte)
	payload = append(payload, ephSPKI...)
	payload = append(payload, iv...)
	payload = append(payload, ct...)

	return Prefix + kid + "." + base64.RawURLEncoding.EncodeToString(payload), nil
}

// Decrypt 以自身私鑰解密。purpose 必須與加密時一致，否則 AAD 不符而回 ERR_AUTH。
func Decrypt(priv *ecdh.PrivateKey, token, purpose string) ([]byte, error) {
	if priv == nil {
		return nil, newErr(ErrKey, "私鑰為 nil")
	}
	if !ValidPurpose(purpose) {
		return nil, newErr(ErrFormat, "purpose 格式非法：%q", purpose)
	}
	t, err := ParseToken(token)
	if err != nil {
		return nil, err
	}

	ephPub, err := PublicKeyFromSPKI(t.EphemeralSPKI)
	if err != nil {
		return nil, err
	}
	shared, err := priv.ECDH(ephPub)
	if err != nil {
		return nil, wrapErr(ErrKey, err, "ECDH 失敗")
	}
	key, err := deriveKey(shared, t.KID, purpose)
	if err != nil {
		return nil, err
	}
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	pt, err := aead.Open(nil, t.IV, t.Ciphertext, aad(t.KID, purpose))
	if err != nil {
		return nil, wrapErr(ErrAuth, err, "GCM 認證失敗")
	}
	return pt, nil
}

func deriveKey(shared []byte, kid, purpose string) ([]byte, error) {
	key, err := hkdf.Key(sha256.New, shared, nil, "cms-key-v1|"+kid+"|"+purpose, KeyLen)
	if err != nil {
		return nil, wrapErr(ErrKey, err, "HKDF 導出失敗")
	}
	return key, nil
}

func aad(kid, purpose string) []byte {
	b := make([]byte, 0, len(kid)+1+len(purpose))
	b = append(b, kid...)
	b = append(b, 0x00)
	b = append(b, purpose...)
	return b
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, wrapErr(ErrKey, err, "建立 AES cipher 失敗")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, wrapErr(ErrKey, err, "建立 GCM 失敗")
	}
	return aead, nil
}

// PublicKeyFromSPKI 解析 DER SubjectPublicKeyInfo，並限制為 P-256。
func PublicKeyFromSPKI(der []byte) (*ecdh.PublicKey, error) {
	pk, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, wrapErr(ErrKey, err, "SPKI 解析失敗")
	}
	ec, ok := pk.(*ecdsa.PublicKey)
	if !ok {
		return nil, newErr(ErrKey, "金鑰型別不是 EC")
	}
	if ec.Curve != elliptic.P256() {
		return nil, newErr(ErrKey, "曲線不是 P-256")
	}
	pub, err := ec.ECDH()
	if err != nil {
		return nil, wrapErr(ErrKey, err, "轉換為 ECDH 公鑰失敗")
	}
	return pub, nil
}

// SPKIFromECDH 把 ECDH 公鑰轉為 DER SubjectPublicKeyInfo（P-256 固定 91 bytes）。
func SPKIFromECDH(pub *ecdh.PublicKey) ([]byte, error) {
	raw := pub.Bytes()
	if len(raw) != 65 {
		return nil, newErr(ErrKey, "公鑰長度 %d，應為 65", len(raw))
	}
	ec := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(raw[1:33]),
		Y:     new(big.Int).SetBytes(raw[33:65]),
	}
	der, err := x509.MarshalPKIXPublicKey(ec)
	if err != nil {
		return nil, wrapErr(ErrKey, err, "SPKI 編碼失敗")
	}
	if len(der) != SPKILen {
		return nil, newErr(ErrKey, "SPKI 長度 %d，應為 91", len(der))
	}
	return der, nil
}

// PrivateKeyFromScalar 由 32 bytes 純量建立私鑰，供測試向量使用。
func PrivateKeyFromScalar(d []byte) (*ecdh.PrivateKey, error) {
	if len(d) != KeyLen {
		return nil, newErr(ErrKey, "私鑰長度 %d，應為 32", len(d))
	}
	priv, err := ecdh.P256().NewPrivateKey(d)
	if err != nil {
		return nil, wrapErr(ErrKey, err, "私鑰純量非法")
	}
	return priv, nil
}
