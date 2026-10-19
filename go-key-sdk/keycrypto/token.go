package keycrypto

import (
	"encoding/base64"
	"strings"
)

// 協定常數。修改任一項即代表協定不相容，必須升版本並重產測試向量。
const (
	Prefix      = "KEY1."
	VersionByte = 1
	SPKILen     = 91 // P-256 SubjectPublicKeyInfo 固定長度
	IVLen       = 12
	TagLen      = 16
	KeyLen      = 32
	MaxTokenLen = 8192
	MaxKIDLen   = 64
	MaxPurpose  = 32
)

// Token 是解析後的密文結構。Ciphertext 已包含 16 bytes 的 GCM tag。
type Token struct {
	KID           string
	EphemeralSPKI []byte
	IV            []byte
	Ciphertext    []byte
}

// ParseToken 只做結構解析，不接觸金鑰。任何格式問題一律回 ERR_FORMAT。
func ParseToken(token string) (*Token, error) {
	if len(token) > MaxTokenLen {
		return nil, newErr(ErrFormat, "token 長度 %d 超過上限 %d", len(token), MaxTokenLen)
	}
	rest, ok := strings.CutPrefix(token, Prefix)
	if !ok {
		return nil, newErr(ErrFormat, "缺少 %q 前綴", Prefix)
	}
	r, body, ok := strings.Cut(rest, ".")
	if !ok {
		return nil, newErr(ErrFormat, "缺少 kid 分隔字元")
	}
	if r == "" {
		return nil, newErr(ErrFormat, "kid 為空")
	}
	if !ValidKID(r) {
		return nil, newErr(ErrFormat, "kid 格式非法：%q", r)
	}

	// RawURLEncoding 本身就會拒絕 '=' 與非 base64url 字元
	payload, err := base64.RawURLEncoding.Strict().DecodeString(body)
	if err != nil {
		return nil, wrapErr(ErrFormat, err, "payload base64url 解碼失敗")
	}
	if len(payload) < 1+SPKILen+IVLen+TagLen {
		return nil, newErr(ErrFormat, "payload 長度 %d 小於最小值 %d", len(payload), 1+SPKILen+IVLen+TagLen)
	}
	if payload[0] != VersionByte {
		return nil, newErr(ErrFormat, "未知版本位元組 0x%02x", payload[0])
	}

	off := 1
	t := &Token{KID: r}
	t.EphemeralSPKI = payload[off : off+SPKILen]
	off += SPKILen
	t.IV = payload[off : off+IVLen]
	off += IVLen
	t.Ciphertext = payload[off:]
	return t, nil
}

// ValidKID：不得含 '.'（分隔字元），長度 1..64，僅允許英數與 _ : -
func ValidKID(kid string) bool {
	if kid == "" || len(kid) > MaxKIDLen {
		return false
	}
	for i := 0; i < len(kid); i++ {
		c := kid[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '_', c == '-', c == ':':
		default:
			return false
		}
	}
	return true
}

// ValidPurpose：^[a-z0-9_-]{1,32}$，且不得含 0x00（AAD 分隔字元）
func ValidPurpose(p string) bool {
	if p == "" || len(p) > MaxPurpose {
		return false
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}
