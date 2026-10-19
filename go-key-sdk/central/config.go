package central

import (
	"encoding/json"
	"fmt"
	"os"
)

// FileConfig 是設定檔格式（JSON）。旗標優先於檔案，環境變數優先於檔案但低於旗標。
// 所有欄位皆可省略，省略時採用預設值。
type FileConfig struct {
	Addr           string   `json:"addr"`            // 監聽位址，預設 :8443
	Cert           string   `json:"cert"`            // 伺服器憑證
	Key            string   `json:"key"`             // 伺服器私鑰
	CA             string   `json:"ca"`              // 用戶端 CA
	AdminToken     string   `json:"admin_token"`     // 管理權杖（API 與後台頁面）
	AdminUser      string   `json:"admin_user"`      // 後台帳號，預設 admin
	KEK            string   `json:"kek"`             // 64 位十六進位；建議改用環境變數 KEY_KEK
	APIAdminToken  string   `json:"api_token"`       // 管理 API 權杖；留空同 admin_token
	SessionSecret  string   `json:"session_secret"`  // 會話簽章密鑰；留空同 admin_token
	AdminCIDR      []string `json:"admin_cidr"`      // 後台允許來源網段
	TrustedProxies []string `json:"trusted_proxies"` // 受信反向代理網段
	ProxySecret    string   `json:"proxy_secret"`    // 代理轉發身分標頭的共享密鑰
	OIDC           *struct {
		Issuer        string            `json:"issuer"`
		ClientID      string            `json:"client_id"`
		ClientSecret  string            `json:"client_secret"`
		RedirectURL   string            `json:"redirect_url"`
		UsernameClaim string            `json:"username_claim"`
		GroupsClaim   string            `json:"groups_claim"`
		DefaultRole   string            `json:"default_role"`
		GroupRoles    map[string]string `json:"group_roles"`
	} `json:"oidc"`
	DSN        string `json:"dsn"`        // MySQL DSN；非空時優先於 data
	Data       string `json:"data"`       // 狀態檔；空字串為純記憶體（重啟即失）
	Audit      string `json:"audit"`      // 稽核 JSONL；空字串只留記憶體
	Grace      string `json:"grace"`      // 例 "5m"
	Prepublish string `json:"prepublish"` // 例 "10m"
	Rotation   string `json:"rotation"`   // 例 "720h"
}

// LoadFileConfig 讀取 JSON 設定檔。
func LoadFileConfig(path string) (*FileConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("讀取設定檔失敗：%w", err)
	}
	var fc FileConfig
	if err := json.Unmarshal(b, &fc); err != nil {
		return nil, fmt.Errorf("設定檔格式錯誤（需為 JSON）：%w", err)
	}
	return &fc, nil
}
