package keycrypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

func FuzzDecryptToken(f *testing.F) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	f.Add("KEY1.SYS-B:1.AAAA")
	f.Add("")
	f.Add("KEY1..")
	f.Fuzz(func(t *testing.T, token string) {
		_, _ = Decrypt(priv, token, "urlparam")
	})
}
