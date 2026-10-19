# 宝塔面板部署要点

宝塔申请的证书就是标准的 Let's Encrypt 证书，和 `certbot` 产物一样，**不影响本项目**。
需要注意的只有路径和「在哪里改配置」。

## 1. 证书路径

宝塔的站点证书固定在这两个位置：

```
/www/server/panel/vhost/cert/<你的域名>/fullchain.pem
/www/server/panel/vhost/cert/<你的域名>/privkey.pem
```

在站点配置里直接引用：

```nginx
ssl_certificate     /www/server/panel/vhost/cert/key.example.com/fullchain.pem;
ssl_certificate_key /www/server/panel/vhost/cert/key.example.com/privkey.pem;
```

> 宝塔续期时会自动覆盖这两个文件并 reload Nginx，路径不变，**不用改配置**。

## 2. 配置改在哪里

**不要**再往 `/etc/nginx/conf.d/` 丢一份 `central-key.conf`，会和宝塔的 vhost 抢同一个 `server_name`。

正確做法：

1. 宝塔 → 网站 → 你的站点 → 设置 → **配置文件**
2. 在现有的 `server { ... }` **里面**，加我们的 `location` 块和 `ssl_client_*` 指令
3. 保存后宝塔会自动 `nginx -t` 并 reload

如果站点原本是 PHP 站点：先把「PHP 版本」设为**纯静态**，删掉默认的
`location ~ \.php$`、`location /` 的静态 root，避免抢请求。

## 3. `central_key_backend` 与 `include` 是什么

原生 nginx 写法里：

```nginx
upstream central_key_backend { server 127.0.0.1:8443; keepalive 32; }
...
proxy_pass https://central_key_backend;
include /etc/nginx/snippets/central-key-headers.conf;
```

- `central_key_backend` 只是 **upstream 的名字**，它最终指向 `127.0.0.1:8443`，不是域名
- `include` 只是把转发头拆到单独文件，避免重复

**宝塔里两个都不需要**：upstream 要写在 http 层（站点配置放不进去），snippets 目录也不存在。
直接写 `proxy_pass https://127.0.0.1:8443;`，把转发头贴进 `location` 即可。

## 4. 要加的片段（宝塔路径版）

放在 `server { }` 里，**证书那两行用宝塔的路径替换掉我们模板里的**：

```nginx
# 用戶端憑證（宝塔面板没有这个选项，必须手写）
ssl_client_certificate /opt/central-key-service/certs/ca.crt;
ssl_verify_client      optional;
ssl_verify_depth       2;

# 系統 API：必須帶有效憑證
location /api/ {
    if ($ssl_client_verify != SUCCESS) {
        return 403;
    }
    proxy_pass https://127.0.0.1:8443;
    proxy_ssl_verify off;

    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_set_header Host              $host;
    proxy_set_header X-Real-IP         $remote_addr;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    # 舊版 nginx 沒有 $ssl_client_s_dn_cn，用 $ssl_client_s_dn（後端會自動取 CN）
    proxy_set_header X-Client-CN       $ssl_client_s_dn;
    proxy_set_header X-Client-Verify   $ssl_client_verify;
    proxy_set_header X-Proxy-Secret    "與 config.json 的 proxy_secret 相同";
    proxy_set_header Authorization     "";
}

# 公網不開後台
location ~ ^/(admin|login|auth|logout) {
    return 403;
}

## 4.1 公網要開後台怎麼配

預設是 `return 403`（不開放）。如果確實要從公網進後台，**至少加 IP 白名單**：

```nginx
location ~ ^/(admin|login|auth|logout) {
    allow 1.2.3.4;          # 你的固定出口 IP
    allow 10.20.0.0/16;     # 辦公網段（可選）
    deny  all;

    proxy_pass https://127.0.0.1:8443;
    proxy_ssl_verify off;
    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_set_header Host              $host;
    proxy_set_header X-Real-IP         $remote_addr;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Client-CN       $ssl_client_s_dn;
    proxy_set_header X-Client-Verify   $ssl_client_verify;
    proxy_set_header X-Proxy-Secret    "與 config.json 相同";
}
```

同時 `config.json` 的 `admin_cidr` 要含同一個 IP（兩層都放行），改完重啟後端。

> 不建議直接把 `/admin` 對全網開放：後台可以停用系統、輪替金鑰，只有共用密碼，沒有 MFA。

## 4.2 進後台之後必須做的事

新增 `SYS-A`、`SYS-B` 兩個系統（**允許 IP 留空**）。沒登記的話，SDK 會回 `{"error":"來源 IP 不符"}`——
訊息容易誤導，實際意思是「查不到這個系統」。

# 健康檢查只給本機
location = /healthz {
    allow 127.0.0.1;
    deny  all;
    proxy_pass https://127.0.0.1:8443;
    proxy_ssl_verify off;
}
```

### 關於 limit_req（先不要加）

如果你看到：

```
nginx: [emerg] zero size shared memory zone "key_api"
```

表示 `limit_req zone=key_api` 用了未定義的 zone。**先整段刪掉 `limit_req` 就能跑**，限流不是必需的（後端本身有登入限流）。

之後要加，`limit_req_zone` 必須放在 **http 上下文**，不是站點配置裡：

1. 編輯 `/www/server/nginx/conf/nginx.conf`
2. 在 `http {` 裡面加一行：

```nginx
limit_req_zone $binary_remote_addr zone=key_api:10m rate=20r/s;
```

3. 再回到站點配置，在 `location /api/` 裡加：

```nginx
limit_req zone=key_api burst=40 nodelay;
```

4. `nginx -t && systemctl reload nginx`

## 5. 三個容易踩的坑

### 4.1 宝塔的「强制 HTTPS」会重复

宝塔开启强制 HTTPS 后，会自动生成 `if ($scheme = http) { return 301 https://...; }`
或一个 80 的 server 块。**不要再加我们的 80 server 块**，保留宝塔那个即可。

### 4.2 伪静态 / 默认 location 抢请求

宝塔站点常带：

```nginx
location / {
    try_files $uri $uri/ /index.php?$query_string;
}
```

它会先匹配掉 `/api/`（如果 `location /api/` 没写对）。确保：
- `/api/` 是前缀匹配且写在 `location /` **之前**（Nginx 前缀匹配按最长路径，不影响顺序，但正则 location 会优先）
- 删除或注释掉 `try_files` 那行，否则 404

### 4.3 不要在面板里重新保存「反向代理」

如果你用了宝塔的「反向代理」功能，面板会重写 vhost 配置，**覆盖你手写的 location**。
建议：不用面板的反代功能，直接在配置文件里写。

改完先备份：

```bash
cp /www/server/panel/vhost/nginx/key.example.com.conf ~/key.example.com.conf.bak
```

## 6. 验证

```bash
nginx -t
systemctl reload nginx

# 無憑證 → 403
curl -s -o /dev/null -w "%{http_code}\n" https://key.example.com/api/v1/sync

# 有憑證 → 200
curl -s --cert /path/SYS-A.crt --key /path/SYS-A.key \
     https://key.example.com/api/v1/sync
```

看 Nginx 有沒有收到憑證：

```bash
tail -f /www/wwwlogs/key.example.com.error.log
# 出現 "client certificate: /CN=SYS-A" 就對了
```

## 7. 後台怎麼進

公網配置下 `/admin` 是 403，用 SSH 隧道：

```bash
ssh -L 8443:127.0.0.1:8443 root@伺服器
# 瀏覽器開 https://127.0.0.1:8443/admin
```

`config.json` 的 `admin_cidr` 要含 `127.0.0.1/32`。

## 8. 一句话

**证书不用动（用宝塔的路径），客户端证书校验必须手写，配置改在宝塔的 vhost 文件里，别新增 conf。**

## 后端配置必须有的三行

宝塔只做反向代理，**后端自己要认得代理转发的身分**，所以 `config.json` 必须包含：

```json
"trusted_proxies": ["127.0.0.1/32"],
"proxy_secret": "与 Nginx 里 X-Proxy-Secret 完全一致",
"admin_cidr": ["127.0.0.1/32", "你的办公 IP/32"]
```

| 字段 | 缺了会怎样 |
|---|---|
| `trusted_proxies` | 后端不信任任何代理头 → 所有系统调用 401 |
| `proxy_secret` | 后端跳过密钥校验（仍要求 `X-Client-Verify: SUCCESS`），安全性下降但不报错 |
| `admin_cidr` | 后台不限来源（不推荐） |

改完重启后端。

## $ssl_client_s_dn_cn 不存在怎么办

`nginx: [emerg] unknown "ssl_client_s_dn_cn" variable` 表示 nginx 版本较旧。
改用所有版本都有的 `$ssl_client_s_dn`，后端会自动从 DN 里取 CN：

```nginx
proxy_set_header X-Client-CN     $ssl_client_s_dn;
proxy_set_header X-Client-Verify $ssl_client_verify;
```

后端接受两种格式：`SYS-A` 或 `/C=CN/O=CMS/CN=SYS-A`。
