// Command vectorcheck 以 Go 跑完整份測試向量，行為與其他語言的 CI 一致。
//
//	go run ./cmd/vectorcheck -vectors ../key-protocol-vectors/v1/vectors.json
//
// 全部通過時 exit 0，任一失敗時 exit 1。
package main

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

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

var pass, fail int

func ok(name string, cond bool, detail string) {
	if cond {
		pass++
		fmt.Printf("  PASS  %s\n", name)
		return
	}
	fail++
	if detail == "" {
		fmt.Printf("  FAIL  %s\n", name)
	} else {
		fmt.Printf("  FAIL  %s  → %s\n", name, detail)
	}
}

func main() {
	path := flag.String("vectors", "", "vectors.json 路徑（預設自動尋找）")
	flag.Parse()

	p, err := resolve(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		fmt.Fprintf(os.Stderr, "解析向量失敗：%v\n", err)
		os.Exit(2)
	}
	fmt.Printf("vectors: %s  protocol=%s v%d  alg=%s\n\n", filepath.Base(p), v.Protocol, v.Version, v.Alg)

	privs := map[string]*ecdh.PrivateKey{}
	spkis := map[string][]byte{}
	for _, k := range v.Keys {
		d, err := hex.DecodeString(k.DHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "d_hex 解析失敗：%v\n", err)
			os.Exit(2)
		}
		priv, err := keycrypto.PrivateKeyFromScalar(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "建立私鑰失敗：%v\n", err)
			os.Exit(2)
		}
		der, err := keycrypto.SPKIFromECDH(priv.PublicKey())
		if err != nil {
			fmt.Fprintf(os.Stderr, "SPKI 編碼失敗：%v\n", err)
			os.Exit(2)
		}
		if got := base64.StdEncoding.EncodeToString(der); got != k.SPKIB64 {
			fmt.Fprintf(os.Stderr, "%s 的 SPKI 與向量不符\n", k.KID)
			os.Exit(2)
		}
		privs[k.KID] = priv
		spkis[k.KID] = der
	}

	fmt.Println("[正向：解密]")
	for _, c := range v.Positive {
		want, err := base64.StdEncoding.DecodeString(c.PlaintextB64)
		if err != nil {
			ok(c.Name, false, "plaintext_b64 解碼失敗")
			continue
		}
		got, err := keycrypto.Decrypt(privs[c.KID], c.Token, c.Purpose)
		if err != nil {
			ok(c.Name, false, err.Error())
			continue
		}
		ok(c.Name, bytes.Equal(got, want), "明文不一致")
	}

	fmt.Println("\n[正向：固定隨機值重現密文]")
	for _, c := range v.Positive {
		pt, _ := base64.StdEncoding.DecodeString(c.PlaintextB64)
		ephD, _ := hex.DecodeString(c.EphDHex)
		iv, _ := hex.DecodeString(c.IVHex)
		got, err := keycrypto.EncryptToWith(spkis[c.KID], c.KID, c.Purpose, pt, ephD, iv)
		if err != nil {
			ok(c.Name, false, err.Error())
			continue
		}
		ok(c.Name, got == c.Token, "密文與向量不符")
	}

	fmt.Println("\n[負向：必須回傳指定錯誤碼]")
	for _, c := range v.Negative {
		want := keycrypto.Code(c.ExpectError)
		priv, exists := privs[c.KID]
		if !exists {
			ok(c.Name, want == keycrypto.ErrUnknownKID, fmt.Sprintf("kid %q 不在金鑰集，但期望 %s", c.KID, want))
			continue
		}
		_, err := keycrypto.Decrypt(priv, c.Token, c.Purpose)
		if err == nil {
			ok(c.Name, false, "預期錯誤但解密成功")
			continue
		}
		got := keycrypto.CodeOf(err)
		ok(c.Name, got == want, fmt.Sprintf("預期 %s，實際 %s", want, got))
	}

	fmt.Printf("\n結果：PASS %d / FAIL %d\n", pass, fail)
	if fail > 0 {
		os.Exit(1)
	}
}

func resolve(p string) (string, error) {
	if p != "" {
		return p, nil
	}
	dir, _ := os.Getwd()
	for i := 0; i < 6; i++ {
		c := filepath.Join(dir, "key-protocol-vectors", "v1", "vectors.json")
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", fmt.Errorf("找不到 key-protocol-vectors/v1/vectors.json，請以 -vectors 指定")
}
