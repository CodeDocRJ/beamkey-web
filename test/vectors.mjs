// Generates docs/test-vectors.json so the Android (Java) crypto can be checked byte-for-byte.
//   npm run vectors
import { writeFileSync } from "node:fs";
import { b64u, deriveSessionBytes, deriveSession, encryptSecret } from "../public/proto.js";

const hex = (u8) => Buffer.from(u8).toString("hex");
const gen = async () => {
  const kp = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const jwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
  return { privateKey: kp.privateKey, publicRaw: new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey)),
           dHex: hex(b64u.dec(jwk.d)) };
};

const phone = await gen(), browser = await gen();
const code = "7KQ2M9XD";
const password = "Pa$$w0rd!@#_+-=[]{}|;':\",./<>?`~Zz";
const fixed = { iv: new Uint8Array([1,2,3,4,5,6,7,8,9,10,11,12]), id: "AQIDBAUGBwgJCgsM" };

const { keyBytes, sas } = await deriveSessionBytes(phone.privateKey, browser.publicRaw, phone.publicRaw, browser.publicRaw);
const { key } = await deriveSession(phone.privateKey, browser.publicRaw, phone.publicRaw, browser.publicRaw);
const msg = await encryptSecret(key, code, password, fixed);

writeFileSync(new URL("../docs/test-vectors.json", import.meta.url), JSON.stringify({
  note: "P-256 ECDH + HKDF-SHA256 + AES-256-GCM. Public keys are 65-byte uncompressed points (base64url, no padding). Private scalars are hex (32 bytes).",
  code,
  phonePrivateD_hex: phone.dHex, phonePub: b64u.enc(phone.publicRaw),
  browserPrivateD_hex: browser.dHex, browserPub: b64u.enc(browser.publicRaw),
  expected: { sas, aesKey_hex: hex(keyBytes) },
  encrypt: { password, iv_hex: hex(fixed.iv), id: fixed.id, aad: code + "|" + fixed.id, ...msg },
}, null, 2));
console.log("wrote docs/test-vectors.json  SAS =", sas);
