package keycrypto_test

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"example.com/key-sdk/keycrypto"
)

type vectorFile struct {
	Protocol string `json:"protocol"`
	Version  int    `json:"version"`
	Alg      string `json:"alg"`
	Keys     []struct {
		KID     string `json:"kid"`
		DHex    string `json:"d_hex"`
		SPKIB64 string `json:"spki_b64"`
	} `json:"keys"`
	Positive []struct {
		Name         string `json:"name"`
		KID          string `json:"kid"`
		Purpose      string `json:"purpose"`
		PlaintextB64 string `json:"plaintext_b64"`
		EphDHex      string `json:"eph_d_hex"`
		IVHex        string `json:"iv_hex"`
		Token        string `json:"token"`
	} `json:"positive"`
	Negative []struct {
		Name        string `json:"name"`
		Token       string `json:"token"`
		KID         string `json:"kid"`
		Purpose     string `json:"purpose"`
		ExpectError string `json:"expect_error"`
	} `json:"negative"`
}

// findVectors 依序嘗試環境變數、相對路徑、向上尋找。
func findVectors(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("KEY_VECTORS"); p != "" {
		return p
	}
	rel := filepath.Join("..", "..", "key-protocol-vectors", "v1", "vectors.json")
	if _, err := os.Stat(rel); err == nil {
		return rel
	}
	dir, _ := os.Getwd()
	for i := 0; i < 6; i++ {
		p := filepath.Join(dir, "key-protocol-vectors", "v1", "vectors.json")
		if _, err := os.Stat(p); err == nil {
			return p
		}
		dir = filepath.Dir(dir)
	}
	t.Fatalf("找不到 vectors.json，可用 KEY_VECTORS 指定路徑")
	return ""
}

func loadVectors(t *testing.T) *vectorFile {
	t.Helper()
	raw, err := os.ReadFile(findVectors(t))
	if err != nil {
		t.Fatalf("讀取向量失敗：%v", err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("解析向量失敗：%v", err)
	}
	if v.Protocol != "cms-key" || v.Version != 1 {
		t.Fatalf("向量協定不符：%s v%d", v.Protocol, v.Version)
	}
	return &v
}

func TestKeyMaterial(t *testing.T) {
	v := loadVectors(t)
	for _, k := range v.Keys {
		t.Run(k.KID, func(t *testing.T) {
			d, err := hex.DecodeString(k.DHex)
			if err != nil {
				t.Fatalf("d_hex 解析失敗：%v", err)
			}
			priv, err := keycrypto.PrivateKeyFromScalar(d)
			if err != nil {
				t.Fatalf("建立私鑰失敗：%v", err)
			}
			der, err := keycrypto.SPKIFromECDH(priv.PublicKey())
			if err != nil {
				t.Fatalf("SPKI 編碼失敗：%v", err)
			}
			if got := base64.StdEncoding.EncodeToString(der); got != k.SPKIB64 {
				t.Fatalf("SPKI 不符")
			}
		})
	}
}

func TestPositiveDecrypt(t *testing.T) {
	v := loadVectors(t)
	privs := privateKeys(t, v)
	for _, c := range v.Positive {
		t.Run(c.Name, func(t *testing.T) {
			want, err := base64.StdEncoding.DecodeString(c.PlaintextB64)
			if err != nil {
				t.Fatalf("plaintext_b64 解碼失敗：%v", err)
			}
			got, err := keycrypto.Decrypt(privs[c.KID], c.Token, c.Purpose)
			if err != nil {
				t.Fatalf("解密失敗：%v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("明文不符：got %d bytes / want %d bytes", len(got), len(want))
			}
		})
	}
}

// TestReproduceCiphertext 是最關鍵的一條：固定隨機值後，密文必須逐字元相同。
func TestReproduceCiphertext(t *testing.T) {
	v := loadVectors(t)
	spkis := spkiByKID(t, v)
	for _, c := range v.Positive {
		t.Run(c.Name, func(t *testing.T) {
			pt, err := base64.StdEncoding.DecodeString(c.PlaintextB64)
			if err != nil {
				t.Fatalf("plaintext_b64 解碼失敗：%v", err)
			}
			ephD, err := hex.DecodeString(c.EphDHex)
			if err != nil {
				t.Fatalf("eph_d_hex 解析失敗：%v", err)
			}
			iv, err := hex.DecodeString(c.IVHex)
			if err != nil {
				t.Fatalf("iv_hex 解析失敗：%v", err)
			}
			got, err := keycrypto.EncryptToWith(spkis[c.KID], c.KID, c.Purpose, pt, ephD, iv)
			if err != nil {
				t.Fatalf("加密失敗：%v", err)
			}
			if got != c.Token {
				t.Fatalf("密文不可重現（HKDF／AAD／佈局任一不一致）\n got=%s\nwant=%s", got, c.Token)
			}
		})
	}
}

func TestNegativeCases(t *testing.T) {
	v := loadVectors(t)
	privs := privateKeys(t, v)
	for _, c := range v.Negative {
		t.Run(c.Name, func(t *testing.T) {
			want := keycrypto.Code(c.ExpectError)
			priv, ok := privs[c.KID]
			if !ok {
				// 金鑰集內查無此 kid，等同 SDK 查表失敗
				if want != keycrypto.ErrUnknownKID {
					t.Fatalf("kid %q 不在金鑰集中，但期望 %s", c.KID, want)
				}
				return
			}
			_, err := keycrypto.Decrypt(priv, c.Token, c.Purpose)
			if err == nil {
				t.Fatalf("預期 %s，實際解密成功", want)
			}
			if got := keycrypto.CodeOf(err); got != want {
				t.Fatalf("預期 %s，實際 %s（%v）", want, got, err)
			}
		})
	}
}

func TestParseTokenRejectsOversize(t *testing.T) {
	big := make([]byte, keycrypto.MaxTokenLen+1)
	for i := range big {
		big[i] = 'A'
	}
	if _, err := keycrypto.ParseToken(string(big)); keycrypto.CodeOf(err) != keycrypto.ErrFormat {
		t.Fatalf("超長 token 應回 ERR_FORMAT，實際 %v", err)
	}
}

func FuzzDecrypt(f *testing.F) {
	seeds := []string{
		"",
		"KEY1.",
		"KEY1.SYS-B:3.",
		"KEY1.SYS-B:3.AAAA",
		"KEY2.SYS-B:3.AAAA",
		"KEY1.bad kid.AAAA",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	priv, err := keycrypto.PrivateKeyFromScalar(bytes.Repeat([]byte{0x01}, 32))
	if err != nil {
		f.Fatalf("建立測試私鑰失敗：%v", err)
	}
	f.Fuzz(func(t *testing.T, token string) {
		// 只驗證不 panic、不洩漏部分明文
		if pt, err := keycrypto.Decrypt(priv, token, "urlparam"); err == nil && pt == nil {
			t.Fatalf("成功但回傳 nil 明文")
		}
	})
}

func privateKeys(t *testing.T, v *vectorFile) map[string]*ecdh.PrivateKey {
	t.Helper()
	m := make(map[string]*ecdh.PrivateKey, len(v.Keys))
	for _, k := range v.Keys {
		d, err := hex.DecodeString(k.DHex)
		if err != nil {
			t.Fatalf("d_hex 解析失敗：%v", err)
		}
		priv, err := keycrypto.PrivateKeyFromScalar(d)
		if err != nil {
			t.Fatalf("建立私鑰失敗：%v", err)
		}
		m[k.KID] = priv
	}
	return m
}

func spkiByKID(t *testing.T, v *vectorFile) map[string][]byte {
	t.Helper()
	m := make(map[string][]byte, len(v.Keys))
	for _, k := range v.Keys {
		der, err := base64.StdEncoding.DecodeString(k.SPKIB64)
		if err != nil {
			t.Fatalf("spki_b64 解碼失敗：%v", err)
		}
		m[k.KID] = der
	}
	return m
}
