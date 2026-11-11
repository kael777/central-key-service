import http from 'node:http';

const PORT = Number(process.env.MOCK_KMS_PORT || 4599);

// 只驗證 AWS SDK 的呼叫路徑，不做真加密；密文就是 base64(plaintext)。
function reply(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'content-type': 'application/x-amz-json-1.1', 'content-length': Buffer.byteLength(body) });
  res.end(body);
}

const server = http.createServer((req, res) => {
  let raw = '';
  req.on('data', (c) => (raw += c));
  req.on('end', () => {
    const target = String(req.headers['x-amz-target'] || '');
    let body = {};
    try {
      body = raw ? JSON.parse(raw) : {};
    } catch {
      return reply(res, 400, { __type: 'SerializationException', message: 'bad json' });
    }
    console.log(target, JSON.stringify(body));
    if (target.endsWith('.Encrypt')) {
      const plain = Buffer.from(body.Plaintext || '', 'base64');
      return reply(res, 200, { CiphertextBlob: plain.toString('base64'), KeyId: body.KeyId || 'mock' });
    }
    if (target.endsWith('.Decrypt')) {
      const cipher = Buffer.from(body.CiphertextBlob || '', 'base64');
      return reply(res, 200, { Plaintext: cipher.toString('base64'), KeyId: body.KeyId || 'mock' });
    }
    if (target.endsWith('.DescribeKey')) {
      return reply(res, 200, {
        KeyMetadata: {
          KeyId: body.KeyId || 'mock',
          Arn: body.KeyId || 'mock',
          Enabled: true,
          KeyState: 'Enabled',
          KeyUsage: 'ENCRYPT_DECRYPT',
        },
      });
    }
    return reply(res, 400, { __type: 'InvalidAction', message: target });
  });
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`mock-kms listening on http://127.0.0.1:${PORT}`);
});
