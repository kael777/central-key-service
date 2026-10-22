// cms-key SDK：網路層（輪詢、快照快取、私鑰取得、降級）
import crypto from 'node:crypto';
import https from 'node:https';
import fs from 'node:fs';
import { performance } from 'node:perf_hooks';
import { URL } from 'node:url';

import { Code, KeyError, decrypt, encrypt, parseToken } from './keycrypto.mjs';

export const MAX_STALENESS_MS = 60_000;
export const POLL_INTERVAL_MS = 30_000;
export const VERSION = '1.0.0';

export class KeyClient {
  constructor({ baseUrl, systemCode, cert, key, ca, timeoutMs = 10_000, maxStalenessMs = MAX_STALENESS_MS }) {
    if (!baseUrl) throw new Error('baseUrl 必填');
    if (!systemCode) throw new Error('systemCode 必填');
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.systemCode = systemCode;
    this.timeoutMs = timeoutMs;
    this.maxStalenessMs = maxStalenessMs;
    this.agent = new https.Agent({
      keepAlive: true,
      cert: cert ? fs.readFileSync(cert) : undefined,
      key: key ? fs.readFileSync(key) : undefined,
      ca: ca ? fs.readFileSync(ca) : undefined,
    });
    this.snapshot = null;
    this.etag = null;
    this.privateKeys = new Map();
  }

  close() {
    this.agent.destroy();
  }

  _request(method, path, body) {
    const url = new URL(this.baseUrl + path);
    const payload = body === undefined ? null : Buffer.from(JSON.stringify(body));
    return new Promise((resolve, reject) => {
      const req = https.request(
        {
          method,
          hostname: url.hostname,
          port: url.port || 443,
          path: url.pathname + url.search,
          agent: this.agent,
          headers: {
            'User-Agent': `key-sdk-node/${VERSION}`,
            Accept: 'application/json',
            ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': payload.length } : {}),
            ...(this.etag && path.includes('/sync') ? { 'If-None-Match': this.etag } : {}),
          },
          timeout: this.timeoutMs,
        },
        (res) => {
          const chunks = [];
          res.on('data', (c) => chunks.push(c));
          res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
        }
      );
      req.on('timeout', () => req.destroy(new KeyError(Code.Unavailable, '請求逾時')));
      req.on('error', (e) => reject(e instanceof KeyError ? e : new KeyError(Code.Unavailable, e.message)));
      if (payload) req.write(payload);
      req.end();
    });
  }

  async refresh() {
    const res = await this._request('GET', '/api/v1/sync');
    if (res.status === 304) {
      if (this.snapshot) this.snapshot.fetchedMono = performance.now();
      return this.snapshot;
    }
    if (res.status === 403 || res.status === 401) throw new KeyError(Code.Unauthorized, '未登記、已停用或憑證無效');
    if (res.status !== 200) throw new KeyError(Code.Unavailable, `中央回應 ${res.status}`);

    const data = JSON.parse(res.body.toString('utf8'));
    const peers = new Map();
    for (const [name, p] of Object.entries(data.peers ?? {})) {
      peers.set(name, {
        kid: p.kid,
        alg: p.alg,
        spki: Buffer.from(p.public_key, 'base64'),
        notBefore: p.not_before,
      });
    }
    this.etag = res.headers.etag ?? null;
    this.snapshot = {
      serverTime: data.server_time,
      mode: data.self?.encryption?.mode ?? 'required',
      policyId: data.self?.encryption?.policy_id,
      policyExpiresAt: data.self?.encryption?.expires_at,
      decryptKIDs: new Set((data.self?.decrypt_versions ?? []).map((v) => v.kid)),
      peers,
      fetchedMono: performance.now(),
    };
    return this.snapshot;
  }

  async _fresh() {
    const age = this.snapshot ? performance.now() - this.snapshot.fetchedMono : Infinity;
    if (this.snapshot && age <= this.maxStalenessMs) return this.snapshot;
    try {
      return await this.refresh();
    } catch (e) {
      if (this.snapshot) throw new KeyError(Code.Stale, `快照已過期且刷新失敗：${e.message}`);
      throw e;
    }
  }

  async encrypt(peerSystem, purpose, plaintext) {
    let snap = await this._fresh();
    if (snap.mode === 'disabled') throw new KeyError(Code.PolicyDisabled, '中央政策為不加密');
    let peer = snap.peers.get(peerSystem);
    if (!peer) {
      snap = await this.refresh();
      peer = snap.peers.get(peerSystem);
      if (!peer) throw new KeyError(Code.UnknownKid, `對端系統未登記：${peerSystem}`);
    }
    return encrypt(peer.spki, peer.kid, purpose, plaintext);
  }

  async decrypt(token, purpose) {
    const t = parseToken(token);
    const priv = await this._privateKey(t.kid);
    return decrypt(priv, token, purpose);
  }

  async _privateKey(kid) {
    if (this.privateKeys.has(kid)) return this.privateKeys.get(kid);
    if (this.snapshot && !this.snapshot.decryptKIDs.has(kid)) {
      await this.refresh();
      if (!this.snapshot.decryptKIDs.has(kid)) throw new KeyError(Code.UnknownKid, `kid 不在授權清單：${kid}`);
    }
    const res = await this._request('POST', '/api/v1/self/private-key', { kid });
    if (res.status === 403 || res.status === 401) throw new KeyError(Code.Unauthorized, '無權取得該私鑰');
    if (res.status === 404) throw new KeyError(Code.UnknownKid, `kid 不存在：${kid}`);
    if (res.status !== 200) throw new KeyError(Code.Unavailable, `私鑰端點回應 ${res.status}`);

    const { private_key_b64 } = JSON.parse(res.body.toString('utf8'));
    const keyObject = crypto.createPrivateKey({ key: Buffer.from(private_key_b64, 'base64'), format: 'der', type: 'pkcs8' });
    this.privateKeys.set(kid, keyObject);
    return keyObject;
  }
}
