// End-to-end protocol test. Start the server first (npm run dev), then: npm test
import WebSocket from "ws";
import assert from "node:assert/strict";
import { b64u, generateKeyPair, deriveSession, encryptSecret, decryptSecret } from "../public/proto.js";

const BASE = process.env.BASE || "http://localhost:8787";
const WSBASE = BASE.replace(/^http/, "ws");
const PASSWORD = "Tr0ub4dor&3-#x!Qz9@Lm$7^p";   // 25 chars with symbols

function open(url, headers = {}) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url, { headers });
    ws.queue = []; ws.waiters = [];
    ws.on("message", (d) => { ws.queue.push(JSON.parse(d.toString())); ws.waiters.splice(0).forEach((f) => f()); });
    ws.on("open", () => resolve(ws));
    ws.on("unexpected-response", (_req, res) => reject(Object.assign(new Error("HTTP " + res.statusCode), { status: res.statusCode })));
    ws.on("error", reject);
  });
}
function next(ws, type, ms = 4000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("timeout waiting for " + type)), ms);
    const pump = () => {
      while (ws.queue.length) {
        const m = ws.queue.shift();
        if (m.t === type) { clearTimeout(timer); return resolve(m); }
      }
      ws.waiters.push(pump);
    };
    pump();
  });
}
const send = (ws, o) => ws.send(JSON.stringify(o));
let passed = 0;
const ok = (name) => { passed++; console.log("  ok  " + name); };

// 1. phone creates a room
const phoneKeys = await generateKeyPair();
let r = await fetch(BASE + "/api/rooms", { method: "POST", body: JSON.stringify({ phonePub: b64u.enc(phoneKeys.publicRaw) }) });
assert.equal(r.status, 201);
const { code, phoneToken, expiresAt } = await r.json();
assert.match(code, /^[0-9A-HJKMNP-TV-Z]{8}$/);
assert.ok(expiresAt > Date.now());
ok("create room -> " + code);

r = await fetch(BASE + "/api/rooms", { method: "POST", body: JSON.stringify({ phonePub: "nope" }) });
assert.equal(r.status, 400); ok("rejects bad public key");

// 2. auth on phone socket
await assert.rejects(open(`${WSBASE}/ws/phone/${code}`, { authorization: "Bearer wrong" }), /401/);
ok("phone socket rejects bad token");
await assert.rejects(open(`${WSBASE}/ws/browser/ZZZZZZZZ`), /404/);
ok("unknown code -> 404");

const phone = await open(`${WSBASE}/ws/phone/${code}`, { authorization: "Bearer " + phoneToken });
const ready = await next(phone, "ready");
assert.equal(ready.browserConnected, false); ok("phone connects with token");

// 3. browser joins (with lower-case + hyphen code, as a human would type it)
const browserKeys = await generateKeyPair();
const humanCode = (code.slice(0, 4) + "-" + code.slice(4)).toLowerCase();
const browser = await open(`${WSBASE}/ws/browser/${humanCode}`);
await next(browser, "connected");
send(browser, { t: "hello", pub: b64u.enc(browserKeys.publicRaw) });
const waiting = await next(browser, "waiting");
const jr = await next(phone, "join_request");
assert.equal(jr.browserPub, b64u.enc(browserKeys.publicRaw));

// second browser while one is pending -> busy
const intruder = await open(`${WSBASE}/ws/browser/${code}`);
send(intruder, { t: "hello", pub: b64u.enc((await generateKeyPair()).publicRaw) });
assert.equal((await next(intruder, "error")).reason, "busy"); ok("second join while pending is refused");

// 4. both sides derive the key and must show the same check code
const browserSession = await deriveSession(browserKeys.privateKey, b64u.dec(waiting.phonePub), b64u.dec(waiting.phonePub), browserKeys.publicRaw);
const phoneSession = await deriveSession(phoneKeys.privateKey, b64u.dec(jr.browserPub), phoneKeys.publicRaw, b64u.dec(jr.browserPub));
assert.equal(browserSession.sas, phoneSession.sas);
ok("check codes match: " + browserSession.sas);

// 5. approve -> encrypted password round trip
send(phone, { t: "approve", reqId: jr.reqId });
await next(browser, "approved"); await next(phone, "paired"); ok("phone approves, browser paired");

const msg = await encryptSecret(phoneSession.key, code, PASSWORD);
assert.ok(!JSON.stringify(msg).includes("Tr0ub4dor"));
send(phone, { t: "send", ...msg });
const got = await next(browser, "secret");
assert.equal(await decryptSecret(browserSession.key, code, got), PASSWORD);
assert.equal((await next(phone, "delivered")).id, msg.id);
send(browser, { t: "copied", id: got.id });
assert.equal((await next(phone, "copied")).id, msg.id);
ok("password encrypted, relayed, decrypted, copy-ack returned");

// tampering / wrong room fails authentication
await assert.rejects(decryptSecret(browserSession.key, "AAAAAAAA", got));
await assert.rejects(decryptSecret(browserSession.key, code, { ...got, ct: got.ct.slice(0, -2) + "AA" }));
ok("tampered ciphertext / wrong room rejected by AES-GCM");

// 6. malformed send is refused
send(phone, { t: "send", id: "x", iv: "short", ct: "short" });
assert.equal((await next(phone, "error")).reason, "bad_send"); ok("malformed send refused");

// 7. browser leaves -> undeliverable
browser.close();
assert.equal((await next(phone, "browser_left")).t, "browser_left");
send(phone, { t: "send", ...(await encryptSecret(phoneSession.key, code, "x")) });
assert.equal((await next(phone, "undeliverable")).reason, "no_browser"); ok("browser leaves -> undeliverable");

// 8. deny x3 locks the room, unlock re-opens it
for (let i = 0; i < 3; i++) {
  const b = await open(`${WSBASE}/ws/browser/${code}`);
  send(b, { t: "hello", pub: b64u.enc((await generateKeyPair()).publicRaw) });
  const j = await next(phone, "join_request");
  send(phone, { t: "deny", reqId: j.reqId });
  await next(b, "denied");
  const d = await next(phone, "denied_ok");
  if (i === 2) assert.equal(d.locked, true);
}
const locked = await open(`${WSBASE}/ws/browser/${code}`);
send(locked, { t: "hello", pub: b64u.enc((await generateKeyPair()).publicRaw) });
assert.equal((await next(locked, "error")).reason, "locked");
send(phone, { t: "unlock" }); await next(phone, "unlocked");
ok("3 denials lock the room; unlock restores it");

// 9. destroy via REST
r = await fetch(`${BASE}/api/rooms/${code}`, { method: "DELETE", headers: { authorization: "Bearer wrong" } });
assert.equal(r.status, 401);
r = await fetch(`${BASE}/api/rooms/${code}`, { method: "DELETE", headers: { authorization: "Bearer " + phoneToken } });
assert.equal(r.status, 204);
assert.equal((await next(phone, "closed")).reason, "destroyed_by_phone");
await assert.rejects(open(`${WSBASE}/ws/browser/${code}`), /404/);
ok("DELETE needs the token and destroys the room");

console.log(`\n${passed} checks passed`);
process.exit(0);
