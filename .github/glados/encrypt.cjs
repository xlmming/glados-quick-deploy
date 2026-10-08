'use strict';
const fs = require('node:fs');
const crypto = require('node:crypto');

function seal(details, reporting) {
  if (!reporting || typeof reporting.publicKey !== 'string' || !/^[a-f0-9]{32}$/.test(reporting.keyId || '')) throw new Error('Report key is not configured');
  const publicKey = crypto.createPublicKey(reporting.publicKey);
  if (publicKey.asymmetricKeyType !== 'rsa' || publicKey.asymmetricKeyDetails.modulusLength < 3072) throw new Error('Invalid report key');
  const aad = Buffer.from(JSON.stringify([details.repository, String(details.runId), details.accountKey]), 'utf8');
  const key = crypto.randomBytes(32); const iv = crypto.randomBytes(12);
  try {
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv); cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(JSON.stringify(details), 'utf8'), cipher.final()]);
    const wrappedKey = crypto.publicEncrypt({ key: publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, key);
    return { schemaVersion: 1, keyId: reporting.keyId, algorithm: 'RSA-OAEP-SHA256+A256GCM',
      aad: aad.toString('base64'), iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'),
      wrappedKey: wrappedKey.toString('base64'), ciphertext: ciphertext.toString('base64') };
  } finally { key.fill(0); }
}
if (require.main === module) {
  try {
    const input = fs.readFileSync(0, 'utf8');
    if (Buffer.byteLength(input) > 256 * 1024) throw new Error('Input limit');
    const config = JSON.parse(fs.readFileSync('.github/glados-accounts.json', 'utf8'));
    process.stdout.write(JSON.stringify(seal(JSON.parse(input), config.reporting)));
  } catch { process.stderr.write('Report encryption failed'); process.exitCode = 1; }
}
module.exports = { seal };
