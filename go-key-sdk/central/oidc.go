package central

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// OIDCConfig 描述外部身分提供者。RoleMapping 依群組對應權限。
type OIDCConfig struct {
	Issuer        string
	ClientID      string
	ClientSecret  string
	RedirectURL   string
	Scopes        []string
	UsernameClaim string
	GroupsClaim   string
	DefaultRole   Role
	GroupRoles    map[string]Role
}

type oidcDiscovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

type oidcClient struct {
	cfg       OIDCConfig
	http      *http.Client
	discovery oidcDiscovery

	mu   sync.RWMutex
	keys map[string]crypto.PublicKey
}

type oidcState struct {
	Nonce    string
	Verifier string
	Exp      time.Time
}

var (
	oidcStatesMu sync.Mutex
	oidcStates   = map[string]oidcState{}
)

func newOIDC(cfg OIDCConfig) (*oidcClient, error) {
	if cfg.Issuer == "" || cfg.ClientID == "" || cfg.RedirectURL == "" {
		return nil, fmt.Errorf("OIDC 設定不完整（issuer/client_id/redirect_url 必填）")
	}
	if cfg.UsernameClaim == "" {
		cfg.UsernameClaim = "preferred_username"
	}
	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = "groups"
	}
	if cfg.DefaultRole == 0 {
		cfg.DefaultRole = RoleViewer
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "profile", "email", "groups"}
	}
	c := &oidcClient{
		cfg:  cfg,
		http: &http.Client{Timeout: 10 * time.Second},
		keys: map[string]crypto.PublicKey{},
	}
	discoURL := strings.TrimRight(cfg.Issuer, "/") + "/.well-known/openid-configuration"
	body, err := c.get(discoURL)
	if err != nil {
		return nil, fmt.Errorf("取得 OIDC discovery 失敗：%w", err)
	}
	if err := json.Unmarshal(body, &c.discovery); err != nil {
		return nil, fmt.Errorf("解析 discovery 失敗：%w", err)
	}
	if c.discovery.AuthorizationEndpoint == "" || c.discovery.TokenEndpoint == "" || c.discovery.JWKSURI == "" {
		return nil, fmt.Errorf("discovery 缺少必要端點")
	}
	return c, nil
}

func (c *oidcClient) get(u string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s 回應 %d", u, resp.StatusCode)
	}
	return body, nil
}

// authURL 產生授權端點 URL，並記錄 state 對應的 nonce／verifier。
func (c *oidcClient) authURL() (string, error) {
	state := randomToken(24)
	nonce := randomToken(24)
	verifier := randomToken(32)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	oidcStatesMu.Lock()
	// 清掉過期的 state，避免長跑記憶體膨脹
	for k, v := range oidcStates {
		if time.Now().After(v.Exp) {
			delete(oidcStates, k)
		}
	}
	oidcStates[state] = oidcState{Nonce: nonce, Verifier: verifier, Exp: time.Now().Add(10 * time.Minute)}
	oidcStatesMu.Unlock()

	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {c.cfg.ClientID},
		"redirect_uri":          {c.cfg.RedirectURL},
		"scope":                 {strings.Join(c.cfg.Scopes, " ")},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	return c.discovery.AuthorizationEndpoint + "?" + q.Encode(), nil
}

// exchange 以授權碼換 id_token，驗章並回傳 claims。
func (c *oidcClient) exchange(ctx context.Context, code, state string) (map[string]any, error) {
	oidcStatesMu.Lock()
	st, ok := oidcStates[state]
	delete(oidcStates, state)
	oidcStatesMu.Unlock()
	if !ok || time.Now().After(st.Exp) {
		return nil, fmt.Errorf("state 無效或已過期")
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {c.cfg.RedirectURL},
		"client_id":     {c.cfg.ClientID},
		"code_verifier": {st.Verifier},
	}
	if c.cfg.ClientSecret != "" {
		form.Set("client_secret", c.cfg.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.discovery.TokenEndpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint 回應 %d：%s", resp.StatusCode, truncate(string(body), 200))
	}
	var tok struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, err
	}
	if tok.IDToken == "" {
		return nil, fmt.Errorf("token 回應缺少 id_token")
	}
	return c.verifyIDToken(tok.IDToken, st.Nonce)
}

func (c *oidcClient) verifyIDToken(idToken, nonce string) (map[string]any, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("id_token 格式錯誤")
	}
	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerRaw, &hdr); err != nil {
		return nil, err
	}

	key, err := c.keyFor(hdr.Kid, hdr.Alg)
	if err != nil {
		return nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	signed := []byte(parts[0] + "." + parts[1])
	sum := sha256.Sum256(signed)

	switch pub := key.(type) {
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
			return nil, fmt.Errorf("id_token 簽章驗證失敗")
		}
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, sum[:], sig) {
			return nil, fmt.Errorf("id_token 簽章驗證失敗")
		}
	default:
		return nil, fmt.Errorf("不支援的金鑰型別")
	}

	payloadRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := json.Unmarshal(payloadRaw, &claims); err != nil {
		return nil, err
	}

	if iss, _ := claims["iss"].(string); strings.TrimRight(iss, "/") != strings.TrimRight(c.cfg.Issuer, "/") {
		return nil, fmt.Errorf("iss 不符")
	}
	if !audContains(claims["aud"], c.cfg.ClientID) {
		return nil, fmt.Errorf("aud 不符")
	}
	if exp, ok := claims["exp"].(float64); !ok || time.Now().Unix() > int64(exp) {
		return nil, fmt.Errorf("id_token 已過期")
	}
	if nonce != "" {
		if n, _ := claims["nonce"].(string); n != nonce {
			return nil, fmt.Errorf("nonce 不符")
		}
	}
	return claims, nil
}

func (c *oidcClient) keyFor(kid, alg string) (crypto.PublicKey, error) {
	c.mu.RLock()
	k, ok := c.keys[kid]
	c.mu.RUnlock()
	if ok {
		return k, nil
	}
	if err := c.refreshKeys(); err != nil {
		return nil, err
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if k, ok := c.keys[kid]; ok {
		return k, nil
	}
	if len(c.keys) == 1 {
		for _, only := range c.keys {
			return only, nil
		}
	}
	return nil, fmt.Errorf("找不到 kid=%s 的公鑰", kid)
}

func (c *oidcClient) refreshKeys() error {
	body, err := c.get(c.discovery.JWKSURI)
	if err != nil {
		return fmt.Errorf("取得 JWKS 失敗：%w", err)
	}
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		return err
	}
	keys := map[string]crypto.PublicKey{}
	for _, j := range set.Keys {
		switch j.Kty {
		case "RSA":
			n, err1 := base64.RawURLEncoding.DecodeString(j.N)
			e, err2 := base64.RawURLEncoding.DecodeString(j.E)
			if err1 != nil || err2 != nil {
				continue
			}
			keys[j.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		case "EC":
			if j.Crv != "P-256" {
				continue
			}
			x, err1 := base64.RawURLEncoding.DecodeString(j.X)
			y, err2 := base64.RawURLEncoding.DecodeString(j.Y)
			if err1 != nil || err2 != nil {
				continue
			}
			keys[j.Kid] = &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		}
	}
	c.mu.Lock()
	c.keys = keys
	c.mu.Unlock()
	return nil
}

// principalFromClaims 依 claims 決定使用者與角色。
func (c *oidcClient) principalFromClaims(claims map[string]any) Principal {
	user, _ := claims[c.cfg.UsernameClaim].(string)
	if user == "" {
		user, _ = claims["email"].(string)
	}
	if user == "" {
		user, _ = claims["sub"].(string)
	}
	role := c.cfg.DefaultRole
	best := Role(0)
	if raw, ok := claims[c.cfg.GroupsClaim]; ok {
		for _, g := range toStrings(raw) {
			if r, ok := c.cfg.GroupRoles[g]; ok && r > best {
				best = r
			}
		}
	}
	if best > 0 {
		role = best
	}
	return Principal{User: user, Role: role}
}

func toStrings(v any) []string {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		return []string{t}
	}
	return nil
}

func audContains(aud any, want string) bool {
	switch t := aud.(type) {
	case string:
		return t == want
	case []any:
		for _, e := range t {
			if s, ok := e.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
