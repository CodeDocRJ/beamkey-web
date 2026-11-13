import { b64u, normalizeCode, generateKeyPair, deriveSession, decryptSecret } from "/proto.js";

const $ = (id) => document.getElementById(id);
const show = (name) => { for (const s of ["join", "verify", "live"]) $("s-" + s).hidden = s !== name; };
const say = (text) => { $("msg").textContent = text || ""; };

let ws = null, pingTimer = null;
let code = null, keys = null, session = null;
let pending = null;           // { id, secret } waiting to be copied; never rendered in the page
let expireTimer = null, clearTimer = null, armed = false;
const seen = new Set();

function reset(message) {
  clearInterval(pingTimer);
  if (ws) { ws.onclose = null; try { ws.close(); } catch {} }
  ws = keys = session = pending = null;
  show("join");
  $("btn-join").disabled = false;
  say(message || "");
}

function setLive(state, text, cls = "") {
  $("state").textContent = state;
  $("dot").className = "dot " + (state === "Phone offline" ? "off" : "on");
  $("live-msg").textContent = text;
  $("live-msg").className = "live-msg " + cls;
}

async function start() {
  code = normalizeCode($("code").value);
  if (!code) { say("That code isn’t valid. It has 8 letters and digits."); return; }
  say("");
  $("btn-join").disabled = true;
  keys = await generateKeyPair();

  const scheme = location.protocol === "https:" ? "wss:" : "ws:";
  ws = new WebSocket(`${scheme}//${location.host}/ws/browser/${code}`);
  ws.onopen = () => ws.send(JSON.stringify({ t: "hello", pub: b64u.enc(keys.publicRaw) }));
  ws.onmessage = (e) => handle(JSON.parse(e.data)).catch(() => say("Something went wrong. Try again."));
  ws.onclose = () => reset("Disconnected. Enter the code again to reconnect.");
  ws.onerror = () => {};
  pingTimer = setInterval(() => ws && ws.readyState === 1 && ws.send('{"t":"ping"}'), 25000);
}

async function handle(m) {
  switch (m.t) {
    case "waiting": {
      const phonePub = b64u.dec(m.phonePub);
      session = await deriveSession(keys.privateKey, phonePub, phonePub, keys.publicRaw);
      $("sas").textContent = session.sas;
      show("verify");
      break;
    }
    case "approved":
      show("live");
      setLive("Connected", "Tap a password on your phone.");
      break;
    case "denied": reset("The phone denied this connection."); break;
    case "phone_offline": if (!$("s-live").hidden) setLive("Phone offline", "Waiting for your phone to reconnect."); break;
    case "phone_online": if (!$("s-live").hidden) setLive("Connected", "Tap a password on your phone."); break;
    case "secret": await onSecret(m); break;
    case "closed": reset(m.reason === "expired" ? "This pairing code expired. Get a new one on your phone." : "The session ended."); break;
    case "error": {
      const text = { busy: "Another connection is waiting for approval. Try again in a minute.",
                     locked: "This room is locked. Unlock it on your phone.",
                     timeout: "The phone didn’t answer in time. Try again." }[m.reason] || "Connection refused.";
      reset(text);
      break;
    }
  }
}

async function onSecret(m) {
  if (!session || seen.has(m.id)) return;
  seen.add(m.id);
  let secret;
  try { secret = await decryptSecret(session.key, code, m); }
  catch { say("Received a message that could not be verified. It was ignored."); return; }

  pending = { id: m.id, secret };
  clearTimeout(expireTimer);
  expireTimer = setTimeout(() => { pending = null; setLive("Connected", "The password expired before it was copied. Send it again.", ""); }, 60000);
  setLive("Connected", "Password received. Click anywhere in this window to copy it.", "ready");
  if (!(await tryCopy())) armGesture();
}

async function tryCopy() {
  if (!pending) return true;
  const { id, secret } = pending;
  try { await navigator.clipboard.writeText(secret); } catch { return false; }
  pending = null;
  clearTimeout(expireTimer);
  setLive("Connected", "Copied. Click the password box and press Ctrl+V.", "done");
  if (ws && ws.readyState === 1) ws.send(JSON.stringify({ t: "copied", id }));
  clearTimeout(clearTimer);
  if ($("clear").checked) {
    clearTimer = setTimeout(() => { if (document.hasFocus()) navigator.clipboard.writeText("").catch(() => {}); }, 30000);
  }
  return true;
}

function armGesture() {
  if (armed) return;
  armed = true;
  const handler = async () => {
    if (await tryCopy()) {
      document.removeEventListener("pointerdown", handler, true);
      document.removeEventListener("keydown", handler, true);
      window.removeEventListener("focus", handler);
      armed = false;
    }
  };
  document.addEventListener("pointerdown", handler, true);
  document.addEventListener("keydown", handler, true);
  window.addEventListener("focus", handler);
}

$("btn-join").addEventListener("click", start);
$("code").addEventListener("keydown", (e) => { if (e.key === "Enter") start(); });
$("btn-cancel").addEventListener("click", () => reset(""));
$("btn-leave").addEventListener("click", () => reset("Disconnected."));
show("join");
$("code").focus();
