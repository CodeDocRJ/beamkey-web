// Fake phone for testing the website before the Android app exists.
//   npm run sim                      (against http://localhost:8787)
//   BASE=https://your.domain npm run sim
import WebSocket from "ws";
import readline from "node:readline";
import { b64u, generateKeyPair, deriveSession, encryptSecret } from "../public/proto.js";

const BASE = process.env.BASE || "http://localhost:8787";
const WSBASE = BASE.replace(/^http/, "ws");
const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const ask = (q) => new Promise((r) => rl.question(q, r));

const keys = await generateKeyPair();
const res = await fetch(BASE + "/api/rooms", { method: "POST", body: JSON.stringify({ phonePub: b64u.enc(keys.publicRaw) }) });
if (res.status !== 201) { console.error("create failed", res.status, await res.text()); process.exit(1); }
const { code, phoneToken, expiresAt } = await res.json();
console.log(`\nPairing code: ${code.slice(0, 4)}-${code.slice(4)}   (expires ${new Date(expiresAt).toLocaleTimeString()})`);
console.log("Open the website, enter the code, then answer the prompts here.\n");

const ws = new WebSocket(`${WSBASE}/ws/phone/${code}`, { headers: { authorization: "Bearer " + phoneToken } });
let session = null;

ws.on("message", async (data) => {
  const m = JSON.parse(data.toString());
  if (m.t === "join_request") {
    const browserPub = b64u.dec(m.browserPub);
    session = await deriveSession(keys.privateKey, browserPub, keys.publicRaw, browserPub);
    console.log(`Browser wants to connect. Check code: ${session.sas}`);
    const a = (await ask("Does the website show the same code? Approve? (y/n) ")).trim().toLowerCase();
    ws.send(JSON.stringify({ t: a === "y" ? "approve" : "deny", reqId: m.reqId }));
  } else if (m.t === "paired") {
    console.log("Paired. Type a password and press Enter to send it, or 'q' to quit.");
    loop();
  } else if (["delivered", "undeliverable", "copied", "browser_left", "closed", "error"].includes(m.t)) {
    console.log("  <-", JSON.stringify(m));
  }
});
ws.on("close", () => { console.log("socket closed"); process.exit(0); });

async function loop() {
  for (; ;) {
    const pw = await ask("password> ");
    if (pw === "q") { ws.send(JSON.stringify({ t: "destroy" })); setTimeout(() => process.exit(0), 300); return; }
    if (!pw || !session) continue;
    ws.send(JSON.stringify({ t: "send", ...(await encryptSecret(session.key, code, pw)) }));
  }
}
