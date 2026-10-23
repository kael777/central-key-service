# OIDC SSO 接入步驟

目標：管理者用公司帳號登入後台，稽核記錄能看到「誰」做了什麼，而不是共用 `admin`。

## 1. 先確認三件事

| 項目 | 要求 |
|---|---|
| 後台網域 | 必須有 HTTPS，例如 `https://key.example.com` |
| IdP | 支援 OIDC（Keycloak、Azure AD、Okta、Google Workspace 都可） |
| 使用者來源網段 | 需列入 `admin_cidr`（因為 `/auth/callback` 受 CIDR 保護） |

## 2. 在 IdP 註冊一個 client

| 欄位 | 填什麼 |
|---|---|
| Application type | Web / Confidential client |
| Redirect URI | `https://key.example.com/auth/callback`（**必須完全一致**） |
| Grant type | Authorization Code |
| Scopes | `openid profile email` |
| Client secret | 記下來，填入設定 |

同時確認 IdP 會在 id_token 帶群組資訊，例如：

```json
{"preferred_username":"alice","groups":["cms-admins"]}
```

不同 IdP 的群組 claim 名稱：

| IdP | 常見 claim |
|---|---|
| Keycloak | `groups`（需加 Group Membership mapper） |
| Azure AD | `groups`（需在 Token configuration 勾選） |
| Okta | `groups` |
| Google Workspace | 沒有群組 claim，需用 `hd` 或自建 mapping |

## 3. 修改 `config.json`

```json
"oidc": {
  "issuer": "https://idp.example.com/realms/cms",
  "client_id": "cms-key",
  "client_secret": "貼上 secret",
  "redirect_url": "https://key.example.com/auth/callback",
  "username_claim": "preferred_username",
  "groups_claim": "groups",
  "default_role": "viewer",
  "group_roles": {
    "cms-admins": "admin",
    "cms-ops": "operator"
  }
}
```

規則：

- `issuer` **不要加結尾斜線**（帶了也可以，程式會處理，但保持一致最省事）
- `redirect_url` 必須與 IdP 註冊的完全一致（https、網域、路徑、有無斜線）
- `default_role`：沒有對應群組時的角色，建議 `viewer`
- `group_roles`：群組 → 角色，未列出的群組忽略

## 4. Nginx 要放行 `/auth/`

公網版設定預設擋掉 `/admin`、`/login`、`/logout`，但 **`/auth/` 必須可達**，否則登入流程會在第一步 403。

`deploy/nginx/central-key-public.conf` 已包含：

```nginx
location ~ ^/(admin|login|logout) {
    return 403;
}
location /auth/ {
    proxy_pass https://central_key_backend;
    include /etc/nginx/snippets/central-key-headers.conf;
}
```

改完 `nginx -t && systemctl reload nginx`。

## 5. 放行使用者來源

`/auth/callback` 走 `adminNetOnly`，所以 `admin_cidr` 必須包含使用者的來源網段：

```json
"admin_cidr": ["127.0.0.1/32", "10.20.0.0/16"]
```

若使用者會從家裡連，需先接 VPN，或另外放寬（不建議直接對全網開放後台）。

## 6. 重啟並驗證

```bash
./central.sh restart
./central.sh logs | tail -20
```

驗證流程：

1. 瀏覽器開 `https://key.example.com/auth/login`
2. 應跳到 IdP 登入頁
3. 登入後回到 `/admin`，右上角顯示你的帳號
4. 做一次輪替，到稽核頁確認 actor 是 **你的使用者名稱**

失敗時的檢查順序：

| 現象 | 原因 |
|---|---|
| `404 未啟用 OIDC` | `oidc.issuer` 沒填或沒重啟 |
| IdP 回 `redirect_uri_mismatch` | 回呼網址不一致 |
| 回 `issuer 不符` | IdP 的 `iss` 與設定不同（常見於 Keycloak 的 realm 路徑） |
| 回 `audience 不符` | `client_id` 與 token 的 `aud` 不同 |
| 登入後是 viewer | `groups` claim 沒帶或群組名稱不符 |
| `403` 在 `/auth/callback` | 你的 IP 不在 `admin_cidr` |

## 7. 啟用後的建議

1. **把共用 token 當緊急入口**：`admin_token` 改成隨機長字串，只放在保險箱
2. 稽核會出現兩種 actor：
   - `alice`（OIDC）
   - `admin`（共用 token）
   若看到 `admin` 就代表有人走了緊急入口，應該追查
3. 定期檢查 IdP 端的登入紀錄與本服務稽核是否對得上

## 8. 與 Java 版的差異

Java 版也支援 OIDC，設定方式相同（`OIDC_ISSUER` 等環境變數），
但沒有 `group_roles` 的 `default_role` 以外的差異；兩邊都通過 mock IdP 測試。
