// Part B (cryptography follow-on): protect one fictional student-data export with AES-256-GCM.
// Uses Node's built-in crypto (OpenSSL). No AES is implemented here.
// Run: npm run partb
import { createCipheriv, createDecipheriv, randomBytes, createHash } from 'node:crypto';

const AAD = Buffer.from('srp-export-v1');   // authenticated but not encrypted: binds the ciphertext to its purpose

function encrypt(key, plaintext) {
  const nonce = randomBytes(12);             // fresh 96-bit nonce for EVERY encryption under this key
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(AAD);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return { nonce, ciphertext, tag: cipher.getAuthTag() };   // 128-bit authentication tag
}

function decrypt(key, { nonce, ciphertext, tag }) {
  const decipher = createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAAD(AAD);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8'); // final() throws if tag fails
}

const hex = (b, n = 16) => `${b.toString('hex').slice(0, n * 2)}${b.length > n ? '...' : ''}`;
const tryDecrypt = (label, key, box) => {
  try { decrypt(key, box); console.log(`${label}: decrypted (UNEXPECTED)`); return false; }
  catch (e) { console.log(`${label}: REJECTED, ${e.message}`); return true; }
};

// Key lives only in memory for this demo. Shown as a fingerprint, never printed.
const key = randomBytes(32);
console.log(`Key: 256-bit, random, in memory only (SHA-256 fingerprint ${createHash('sha256').update(key).digest('hex').slice(0, 12)}...)\n`);

const record = JSON.stringify({ studentId: 'S001', name: 'Ama Mensah', course: 'C101', grade: 'B+', note: 'synthetic record' });
console.log(`Plaintext record: ${record}\n`);

// 1. Encrypt and decrypt
const box = encrypt(key, record);
console.log('1. Encrypt and decrypt');
console.log(`   nonce      ${hex(box.nonce)} (${box.nonce.length * 8} bits)`);
console.log(`   ciphertext ${hex(box.ciphertext)} (${box.ciphertext.length} bytes)`);
console.log(`   tag        ${hex(box.tag)} (${box.tag.length * 8} bits)`);
const restored = decrypt(key, box);
console.log(`   decrypted  ${restored}`);
console.log(`   identical to original: ${restored === record}\n`);

// 2. Fresh nonce: same key, same record, different nonce and different ciphertext
const box2 = encrypt(key, record);
console.log('2. Fresh nonce per encryption (same key, same record)');
console.log(`   nonce #1 ${hex(box.nonce)}   ciphertext #1 ${hex(box.ciphertext, 12)}`);
console.log(`   nonce #2 ${hex(box2.nonce)}   ciphertext #2 ${hex(box2.ciphertext, 12)}`);
console.log(`   nonces differ: ${!box.nonce.equals(box2.nonce)}; ciphertexts differ: ${!box.ciphertext.equals(box2.ciphertext)}\n`);

// 3. Integrity: alter one ciphertext byte, then one tag byte, in local copies
console.log('3. Tamper tests (local copies)');
const badCt = Buffer.from(box.ciphertext); badCt[5] ^= 0x01;
const badTag = Buffer.from(box.tag); badTag[0] ^= 0x01;
const ok1 = tryDecrypt('   ciphertext byte 5 flipped', key, { ...box, ciphertext: badCt });
const ok2 = tryDecrypt('   tag byte 0 flipped       ', key, { ...box, tag: badTag });
const ok3 = tryDecrypt('   wrong key                ', randomBytes(32), box);
console.log(`\nAll tamper attempts rejected: ${ok1 && ok2 && ok3}`);
console.log('\nWhy nonce reuse is dangerous: GCM encrypts by XOR with a keystream derived from key + nonce.');
console.log('Reusing a nonce with the same key reuses the keystream, so XOR of two ciphertexts = XOR of the');
console.log('two plaintexts, and it exposes the authentication key, letting an attacker forge valid tags.');
