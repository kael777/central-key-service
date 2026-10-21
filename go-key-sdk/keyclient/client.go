// Package keyclient 實作 SDK 的網路層：輪詢 /sync、快取快照、私鑰取得與降級判斷。
// 業務系統只需要這一層；密碼學全部委派給 keycrypto。
package keyclient

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"example.com/key-sdk/keycrypto"
)

// MaxStaleness 是快照的硬上限，與協定綁定，不應由設定調整。
var MaxStaleness = 60 * time.Second

// PollInterval 是建議的輪詢間隔，同樣與 5 分鐘緩衝期綁定。
const PollInterval = 30 * time.Second

// Config 描述一個接入系統。
type Config struct {
	BaseURL    string // 例：https://key.internal
	SystemCode string // 例：SYS-A
	ClientCert string // mTLS 用戶端憑證（PEM）
	ClientKey  string
	CAFile     string       // 內網 CA（PEM）
	HTTPClient *http.Client // 非 nil 時忽略上面三項，供測試注入
	UserAgent  string       // 預設 key-sdk-go/{Version}
}

// Version 由 CI 於建置時以 -ldflags 覆寫。
var Version = "dev"

// Peer 是對端系統目前的加密公鑰。
type Peer struct {
	KID       string
	SPKI      []byte
	NotBefore time.Time
}

// Snapshot 是一次 /sync 的原子快照。
type Snapshot struct {
	ServerTime  time.Time
	FetchedAt   time.Time
	ETag        string
	Mode        string // required / optional / disabled
	Peers       map[string]Peer
	DecryptKIDs map[string]bool
}

// Client 是並發安全的。
type Client struct {
	cfg  Config
	hc   *http.Client
	mu   sync.RWMutex
	snap *Snapshot
	etag string
	priv map[string]*ecdh.PrivateKey
}

// New 建立 Client。憑證採延遲載入，New 本身不做網路動作。
func New(cfg Config) (*Client, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("keyclient: BaseURL 不可為空")
	}
	if cfg.SystemCode == "" {
		return nil, fmt.Errorf("keyclient: SystemCode 不可為空")
	}
	c := &Client{cfg: cfg, priv: make(map[string]*ecdh.PrivateKey)}
	if cfg.HTTPClient != nil {
		c.hc = cfg.HTTPClient
		return c, nil
	}
	tlsCfg, err := clientTLS(cfg)
	if err != nil {
		return nil, err
	}
	c.hc = &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg, MaxIdleConnsPerHost: 4},
	}
	return c, nil
}

func clientTLS(cfg Config) (*tls.Config, error) {
	if cfg.ClientCert == "" || cfg.ClientKey == "" {
		return nil, fmt.Errorf("keyclient: 需要 mTLS 憑證（ClientCert／ClientKey）")
	}
	cert, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
	if err != nil {
		return nil, fmt.Errorf("keyclient: 載入用戶端憑證失敗: %w", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("keyclient: 讀取 CA 失敗: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("keyclient: CA 檔案無有效憑證")
		}
		tlsCfg.RootCAs = pool
	}
	return tlsCfg, nil
}

func (c *Client) userAgent() string {
	if c.cfg.UserAgent != "" {
		return c.cfg.UserAgent
	}
	return "key-sdk-go/" + Version
}

// Refresh 取得最新快照。304 時只更新 FetchedAt。
func (c *Client) Refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.BaseURL+"/api/v1/sync", nil)
	if err != nil {
		return &keycrypto.Error{Code: keycrypto.ErrUnavailable, Msg: "建立請求失敗", Err: err}
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent())
	c.mu.RLock()
	etag := c.etag
	c.mu.RUnlock()
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return &keycrypto.Error{Code: keycrypto.ErrUnavailable, Msg: "呼叫 /sync 失敗", Err: err}
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusNotModified:
		c.mu.Lock()
		if c.snap != nil {
			c.snap.FetchedAt = time.Now()
		}
		c.mu.Unlock()
		return nil
	case resp.StatusCode == http.StatusForbidden:
		return &keycrypto.Error{Code: keycrypto.ErrUnauthorized, Msg: "未登記、已停用或來源 IP 不符"}
	case resp.StatusCode >= 500:
		return &keycrypto.Error{Code: keycrypto.ErrUnavailable, Msg: fmt.Sprintf("中央回應 %d", resp.StatusCode)}
	case resp.StatusCode != http.StatusOK:
		return &keycrypto.Error{Code: keycrypto.ErrUnavailable, Msg: fmt.Sprintf("非預期狀態碼 %d", resp.StatusCode)}
	}

	hdrETag := resp.Header.Get("ETag")
	var sr syncResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&sr); err != nil {
		return &keycrypto.Error{Code: keycrypto.ErrUnavailable, Msg: "解析 /sync 回應失敗", Err: err}
	}
	snap, err := sr.toSnapshot()
	if err != nil {
		return err
	}
	snap.FetchedAt = time.Now()
	if hdrETag != "" {
		snap.ETag = hdrETag
	}
	c.mu.Lock()
	c.snap = snap
	if snap.ETag != "" {
		c.etag = snap.ETag
	}
	c.mu.Unlock()
	return nil
}

// Snapshot 回傳目前快照（可能為 nil）。
func (c *Client) Snapshot() *Snapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.snap
}

// fresh 確保快照未過期；過期則嘗試刷新一次。
func (c *Client) fresh(ctx context.Context) (*Snapshot, error) {
	s := c.Snapshot()
	if s != nil && time.Since(s.FetchedAt) <= MaxStaleness {
		return s, nil
	}
	if err := c.Refresh(ctx); err != nil {
		if s != nil {
			return nil, &keycrypto.Error{Code: keycrypto.ErrStale, Msg: "快照已過期且刷新失敗", Err: err}
		}
		return nil, err
	}
	return c.Snapshot(), nil
}

// Encrypt 以對端系統的公鑰加密。
func (c *Client) Encrypt(ctx context.Context, peerSystem, purpose string, plaintext []byte) (string, error) {
	s, err := c.fresh(ctx)
	if err != nil {
		return "", err
	}
	if s.Mode == "disabled" {
		return "", &keycrypto.Error{Code: keycrypto.ErrPolicyDisabled, Msg: "中央政策為不加密"}
	}
	peer, ok := s.Peers[peerSystem]
	if !ok {
		if err := c.Refresh(ctx); err != nil {
			return "", err
		}
		s = c.Snapshot()
		if peer, ok = s.Peers[peerSystem]; !ok {
			return "", &keycrypto.Error{Code: keycrypto.ErrUnknownKID, Msg: "對端系統未登記: " + peerSystem}
		}
	}
	return keycrypto.EncryptTo(peer.SPKI, peer.KID, purpose, plaintext)
}

// Decrypt 依密文版本取得對應私鑰並解密；未知版本會強制刷新一次。
func (c *Client) Decrypt(ctx context.Context, token, purpose string) ([]byte, error) {
	t, err := keycrypto.ParseToken(token)
	if err != nil {
		return nil, err
	}
	priv, err := c.privateKey(ctx, t.KID)
	if err != nil {
		return nil, err
	}
	return keycrypto.Decrypt(priv, token, purpose)
}

func (c *Client) privateKey(ctx context.Context, kid string) (*ecdh.PrivateKey, error) {
	c.mu.RLock()
	p, ok := c.priv[kid]
	c.mu.RUnlock()
	if ok {
		return p, nil
	}
	s := c.Snapshot()
	if s != nil && !s.DecryptKIDs[kid] {
		if err := c.Refresh(ctx); err != nil {
			return nil, err
		}
		s = c.Snapshot()
		if s == nil || !s.DecryptKIDs[kid] {
			return nil, &keycrypto.Error{Code: keycrypto.ErrUnknownKID, Msg: "kid 不在授權清單: " + kid}
		}
	}
	p, err := c.fetchPrivateKey(ctx, kid)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.priv[kid] = p
	c.mu.Unlock()
	return p, nil
}

func (c *Client) fetchPrivateKey(ctx context.Context, kid string) (*ecdh.PrivateKey, error) {
	body, _ := json.Marshal(map[string]string{"kid": kid})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.BaseURL+"/api/v1/self/private-key", bytes.NewReader(body))
	if err != nil {
		return nil, &keycrypto.Error{Code: keycrypto.ErrUnavailable, Msg: "建立請求失敗", Err: err}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.userAgent())

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, &keycrypto.Error{Code: keycrypto.ErrUnavailable, Msg: "取得私鑰失敗", Err: err}
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusForbidden, http.StatusUnauthorized:
		return nil, &keycrypto.Error{Code: keycrypto.ErrUnauthorized, Msg: "無權取得該私鑰"}
	case http.StatusNotFound:
		return nil, &keycrypto.Error{Code: keycrypto.ErrUnknownKID, Msg: "kid 不存在: " + kid}
	default:
		return nil, &keycrypto.Error{Code: keycrypto.ErrUnavailable, Msg: fmt.Sprintf("私鑰端點回應 %d", resp.StatusCode)}
	}

	var pr pkResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&pr); err != nil {
		return nil, &keycrypto.Error{Code: keycrypto.ErrUnavailable, Msg: "解析私鑰回應失敗", Err: err}
	}
	der, err := base64.StdEncoding.DecodeString(pr.PrivateKeyB64)
	if err != nil {
		return nil, &keycrypto.Error{Code: keycrypto.ErrKey, Msg: "私鑰 base64 解碼失敗", Err: err}
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, &keycrypto.Error{Code: keycrypto.ErrKey, Msg: "私鑰解析失敗", Err: err}
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, &keycrypto.Error{Code: keycrypto.ErrKey, Msg: "私鑰型別不是 EC"}
	}
	ep, err := ec.ECDH()
	if err != nil {
		return nil, &keycrypto.Error{Code: keycrypto.ErrKey, Msg: "私鑰轉換失敗", Err: err}
	}
	return ep, nil
}

type syncResponse struct {
	ServerTime string `json:"server_time"`
	Self       struct {
		SystemCode string `json:"system_code"`
		Encryption struct {
			Mode string `json:"mode"`
		} `json:"encryption"`
		DecryptVersions []struct {
			KID string `json:"kid"`
		} `json:"decrypt_versions"`
	} `json:"self"`
	Peers map[string]struct {
		KID       string `json:"kid"`
		Alg       string `json:"alg"`
		PublicKey string `json:"public_key"`
		NotBefore string `json:"not_before"`
	} `json:"peers"`
	ETag string `json:"etag"`
}

func (sr *syncResponse) toSnapshot() (*Snapshot, error) {
	s := &Snapshot{
		Mode:        sr.Self.Encryption.Mode,
		Peers:       make(map[string]Peer, len(sr.Peers)),
		DecryptKIDs: make(map[string]bool, len(sr.Self.DecryptVersions)),
		ETag:        sr.ETag,
	}
	if t, err := time.Parse(time.RFC3339, sr.ServerTime); err == nil {
		s.ServerTime = t
	}
	for name, p := range sr.Peers {
		der, err := base64.StdEncoding.DecodeString(p.PublicKey)
		if err != nil {
			return nil, &keycrypto.Error{Code: keycrypto.ErrKey, Msg: "對端公鑰 base64 解碼失敗: " + name}
		}
		if _, err := keycrypto.PublicKeyFromSPKI(der); err != nil {
			return nil, err
		}
		nb, _ := time.Parse(time.RFC3339, p.NotBefore)
		s.Peers[name] = Peer{KID: p.KID, SPKI: der, NotBefore: nb}
	}
	for _, v := range sr.Self.DecryptVersions {
		s.DecryptKIDs[v.KID] = true
	}
	return s, nil
}

type pkResponse struct {
	KID           string `json:"kid"`
	PrivateKeyB64 string `json:"private_key_b64"`
}
