// Shared protocol helpers. Runs unchanged in the browser, in Cloudflare Workers and in Node 20+.
// Wire format reference: docs/API.md

const enc = new TextEncoder();
const dec = new TextDecoder();

export const CODE_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"; // Crockford base32 (32 symbols)
export const PAD = 128;           // plaintext is padded to 128 bytes: [len_hi][len_lo][password...][zeros]
export const MAX_PASSWORD_BYTES = PAD - 2;

export const b64u = {
  enc(bytes) {
    let s = "";
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  },
  dec(str) {
    let s = str.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  },
};

/** Accepts "abcd-efgh", " ABCD EFGH " etc. Returns the canonical 8-char code or null. */
export function normalizeCode(input) {
  const s = String(input || "").toUpperCase().replace(/[\s-]/g, "")
    .replace(/O/g, "0").replace(/[IL]/g, "1");
  return /^[0-9A-HJKMNP-TV-Z]{8}$/.test(s) ? s : null;
}

/** True if s is a base64url uncompressed P-256 public key (65 bytes, 0x04 prefix). */
export function validPub(s) {
  if (typeof s !== "string" || s.length !== 87) return false;
  try { const b = b64u.dec(s); return b.length === 65 && b[0] === 4; } catch { return false; }
}

const concat = (...arrs) => {
  const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0));
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
};

export async function generateKeyPair() {
  const kp = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const publicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  return { privateKey: kp.privateKey, publicRaw };
}

function toSas(hash) {
  let bits = 0n;
  for (let i = 0; i < 5; i++) bits = (bits << 8n) | BigInt(hash[i]);
  let s = "";
  for (let i = 7; i >= 0; i--) s += CODE_ALPHABET[Number((bits >> BigInt(i * 5)) & 31n)];
  return s.slice(0, 4) + "-" + s.slice(4);
}

/** Derives the session AES key bytes and the short check code (SAS) both sides must compare. */
export async function deriveSessionBytes(privateKey, peerPubRaw, phonePubRaw, browserPubRaw) {
  const peer = await crypto.subtle.importKey("raw", peerPubRaw, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: peer }, privateKey, 256));
  const salt = new Uint8Array(await crypto.subtle.digest("SHA-256", concat(phonePubRaw, browserPubRaw)));
  const hk = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveBits"]);
  const keyBytes = new Uint8Array(await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt, info: enc.encode("rcvpass-v1 aes-gcm") }, hk, 256));
  const sasHash = new Uint8Array(await crypto.subtle.digest("SHA-256",
    concat(enc.encode("rcvpass-v1 sas"), phonePubRaw, browserPubRaw)));
  return { keyBytes, sas: toSas(sasHash) };
}

export async function deriveSession(privateKey, peerPubRaw, phonePubRaw, browserPubRaw) {
  const { keyBytes, sas } = await deriveSessionBytes(privateKey, peerPubRaw, phonePubRaw, browserPubRaw);
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt", "decrypt"]);
  return { key, sas };
}

export async function encryptSecret(key, code, password, fixed = {}) {
  const pw = enc.encode(password);
  if (pw.length > MAX_PASSWORD_BYTES) throw new Error("password too long");
  const plain = new Uint8Array(PAD);
  plain[0] = pw.length >> 8; plain[1] = pw.length & 255; plain.set(pw, 2);
  const iv = fixed.iv || crypto.getRandomValues(new Uint8Array(12));
  const id = fixed.id || b64u.enc(crypto.getRandomValues(new Uint8Array(12)));
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: enc.encode(code + "|" + id) }, key, plain));
  return { id, iv: b64u.enc(iv), ct: b64u.enc(ct) };
}

export async function decryptSecret(key, code, { id, iv, ct }) {
  const plain = new Uint8Array(await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64u.dec(iv), additionalData: enc.encode(code + "|" + id) }, key, b64u.dec(ct)));
  const n = (plain[0] << 8) | plain[1];
  if (plain.length !== PAD || n > PAD - 2) throw new Error("bad padding");
  return dec.decode(plain.subarray(2, 2 + n));
}
