import { DurableObject } from "cloudflare:workers";
import { b64u, validPub } from "../public/proto.js";

const MAX_MSG_CHARS = 4096;
const PENDING_TTL_MS = 120_000;   // a join request waits this long for the phone to answer
const MAX_DENIALS = 3;            // after this many "Deny" taps the room refuses new joins until the phone unlocks it
const SEND_LIMIT = { count: 20, windowMs: 60_000 };
const OPEN = 1;

const J = (o) => JSON.stringify(o);
const rand = (n = 12) => b64u.enc(crypto.getRandomValues(new Uint8Array(n)));
const safeSend = (ws, obj) => { try { ws.send(J(obj)); } catch {} };
const safeClose = (ws, code = 1000, reason = "bye") => { try { ws.close(code, reason); } catch {} };
const idOk = (s) => typeof s === "string" && /^[A-Za-z0-9_-]{1,32}$/.test(s);

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

async function tokenMatches(request, room) {
  const h = request.headers.get("authorization") || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : "";
  if (!token) return false;
  const hash = b64u.enc(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token))));
  return safeEqual(hash, room.tokenHash);
}

/**
 * One Room = one phone + at most one active browser. The server only relays ciphertext.
 * Durable Object name == room code, so rooms are fully isolated from each other.
 */
export class Room extends DurableObject {
  sendTimes = [];

  getRoom() { return this.ctx.storage.get("room").then((r) => r || null); }
  putRoom(r) { return this.ctx.storage.put("room", r); }

  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === "/init") return this.init(request);
    if (url.pathname === "/destroy") return this.destroyHttp(request);
    const m = url.pathname.match(/^\/ws\/(phone|browser)\//);
    if (m) return this.connect(request, m[1]);
    return new Response("not found", { status: 404 });
  }

  // ---------- HTTP-ish entry points (called by the Worker) ----------

  async init(request) {
    if (await this.getRoom()) return new Response("exists", { status: 409 });
    const { code, phonePub, tokenHash, ttl } = await request.json();
    const now = Date.now();
    const room = {
      code, phonePub, tokenHash,
      createdAt: now, expiresAt: now + ttl * 1000,
      denials: 0, locked: false, pending: null,
    };
    await this.putRoom(room);
    await this.ctx.storage.setAlarm(room.expiresAt);
    return Response.json({ expiresAt: room.expiresAt }, { status: 201 });
  }

  async destroyHttp(request) {
    const room = await this.getRoom();
    if (!room) return Response.json({ error: "not_found" }, { status: 404 });
    if (!(await tokenMatches(request, room))) return Response.json({ error: "unauthorized" }, { status: 401 });
    await this.destroy("destroyed_by_phone");
    return new Response(null, { status: 204 });
  }

  async connect(request, role) {
    const room = await this.getRoom();
    if (!room || Date.now() >= room.expiresAt) {
      if (room) await this.destroy("expired");
      return Response.json({ error: "not_found" }, { status: 404 });
    }
    if (request.headers.get("Upgrade") !== "websocket") return new Response("Expected websocket", { status: 426 });
    if (role === "phone" && !(await tokenMatches(request, room))) {
      return Response.json({ error: "unauthorized" }, { status: 401 });
    }

    const [client, server] = Object.values(new WebSocketPair());

    if (role === "phone") {
      for (const s of this.ctx.getWebSockets("phone")) safeClose(s, 1000, "replaced");
      this.ctx.acceptWebSocket(server, ["phone"]);
      server.serializeAttachment({ role: "phone" });
      safeSend(server, { t: "ready", expiresAt: room.expiresAt, browserConnected: !!this.activeBrowser() });
      if (room.pending && Date.now() - room.pending.at < PENDING_TTL_MS) {
        safeSend(server, { t: "join_request", reqId: room.pending.reqId, browserPub: room.pending.pub });
      }
      this.toBrowsers({ t: "phone_online" });
    } else {
      this.ctx.acceptWebSocket(server, ["browser"]);
      server.serializeAttachment({ role: "browser", bid: rand(8), state: "new" });
      safeSend(server, { t: "connected" });
    }
    return new Response(null, { status: 101, webSocket: client });
  }

  // ---------- helpers ----------

  browserSockets() { return this.ctx.getWebSockets("browser").filter((s) => s.readyState === OPEN); }
  phoneSocket() { return this.ctx.getWebSockets("phone").find((s) => s.readyState === OPEN) || null; }
  browserByBid(bid, state) {
    return this.browserSockets().find((s) => {
      const a = s.deserializeAttachment() || {};
      return a.bid === bid && (!state || a.state === state);
    }) || null;
  }
  activeBrowser() {
    return this.browserSockets().find((s) => (s.deserializeAttachment() || {}).state === "active") || null;
  }
  toBrowsers(msg) { for (const s of this.browserSockets()) safeSend(s, msg); }

  async destroy(reason) {
    for (const s of this.ctx.getWebSockets()) { safeSend(s, { t: "closed", reason }); safeClose(s, 1000, reason); }
    await this.ctx.storage.deleteAlarm();
    await this.ctx.storage.deleteAll();
  }

  async alarm() { await this.destroy("expired"); }

  // ---------- WebSocket events (hibernation API) ----------

  async webSocketMessage(ws, message) {
    if (typeof message !== "string" || message.length > MAX_MSG_CHARS) { safeClose(ws, 1009, "too big"); return; }
    let m;
    try { m = JSON.parse(message); } catch { return; }
    if (!m || typeof m !== "object") return;
    if (m.t === "ping") { safeSend(ws, { t: "pong" }); return; }
    const att = ws.deserializeAttachment() || {};
    if (att.role === "browser") return this.onBrowser(ws, att, m);
    if (att.role === "phone") return this.onPhone(ws, m);
  }

  async onBrowser(ws, att, m) {
    if (m.t === "copied" && att.state === "active" && idOk(m.id)) {
      const phone = this.phoneSocket();
      if (phone) safeSend(phone, { t: "copied", id: m.id });
      return;
    }
    if (m.t !== "hello" || att.state !== "new") return;

    if (!validPub(m.pub)) { safeSend(ws, { t: "error", reason: "bad_pub" }); safeClose(ws, 1008, "bad pub"); return; }
    const room = await this.getRoom();
    if (!room) { safeClose(ws, 1000, "gone"); return; }
    if (room.locked) { safeSend(ws, { t: "error", reason: "locked" }); safeClose(ws, 1008, "locked"); return; }

    const now = Date.now();
    if (room.pending) {
      if (now - room.pending.at < PENDING_TTL_MS) {
        safeSend(ws, { t: "error", reason: "busy" });
        safeClose(ws, 1008, "busy");
        return;
      }
      const stale = this.browserByBid(room.pending.bid);   // stale request: drop it
      if (stale) { safeSend(stale, { t: "error", reason: "timeout" }); safeClose(stale, 1000, "timeout"); }
    }
    room.pending = { reqId: rand(12), pub: m.pub, bid: att.bid, at: now };
    await this.putRoom(room);
    att.state = "pending";
    ws.serializeAttachment(att);

    safeSend(ws, { t: "waiting", phonePub: room.phonePub, expiresAt: room.expiresAt });
    const phone = this.phoneSocket();
    if (phone) safeSend(phone, { t: "join_request", reqId: room.pending.reqId, browserPub: m.pub });
  }

  async onPhone(ws, m) {
    const room = await this.getRoom();
    if (!room) return;

    switch (m.t) {
      case "approve": {
        const p = room.pending;
        if (!p || p.reqId !== m.reqId) { safeSend(ws, { t: "error", reason: "no_pending" }); return; }
        const target = this.browserByBid(p.bid, "pending");
        room.pending = null;
        await this.putRoom(room);
        if (!target) { safeSend(ws, { t: "join_cancelled" }); return; }
        const old = this.activeBrowser();
        if (old) { safeSend(old, { t: "closed", reason: "replaced" }); safeClose(old, 1000, "replaced"); }
        const a = target.deserializeAttachment();
        a.state = "active";
        target.serializeAttachment(a);
        safeSend(target, { t: "approved" });
        safeSend(ws, { t: "paired" });
        return;
      }
      case "deny": {
        const p = room.pending;
        if (!p || p.reqId !== m.reqId) { safeSend(ws, { t: "error", reason: "no_pending" }); return; }
        room.pending = null;
        room.denials++;
        if (room.denials >= MAX_DENIALS) room.locked = true;
        await this.putRoom(room);
        const target = this.browserByBid(p.bid);
        if (target) { safeSend(target, { t: "denied" }); safeClose(target, 1000, "denied"); }
        safeSend(ws, { t: "denied_ok", locked: room.locked });
        return;
      }
      case "unlock": {
        room.locked = false;
        room.denials = 0;
        await this.putRoom(room);
        safeSend(ws, { t: "unlocked" });
        return;
      }
      case "send": {
        if (!idOk(m.id) || typeof m.iv !== "string" || m.iv.length !== 16 ||
            typeof m.ct !== "string" || m.ct.length < 16 || m.ct.length > 400) {
          safeSend(ws, { t: "error", reason: "bad_send" });
          return;
        }
        const now = Date.now();
        this.sendTimes = this.sendTimes.filter((x) => now - x < SEND_LIMIT.windowMs);
        if (this.sendTimes.length >= SEND_LIMIT.count) { safeSend(ws, { t: "error", reason: "rate_limited" }); return; }
        this.sendTimes.push(now);

        const b = this.activeBrowser();
        if (!b) { safeSend(ws, { t: "undeliverable", id: m.id, reason: "no_browser" }); return; }
        safeSend(b, { t: "secret", id: m.id, iv: m.iv, ct: m.ct, ts: now });   // relayed, never stored
        safeSend(ws, { t: "delivered", id: m.id });
        return;
      }
      case "destroy":
        await this.destroy("destroyed_by_phone");
        return;
    }
  }

  async webSocketClose(ws, code) {
    const att = ws.deserializeAttachment() || {};
    safeClose(ws, code >= 1000 && code <= 4999 && ![1005, 1006, 1015].includes(code) ? code : 1000, "bye");

    if (att.role === "phone") {
      const others = this.ctx.getWebSockets("phone").filter((s) => s !== ws && s.readyState === OPEN);
      if (!others.length) this.toBrowsers({ t: "phone_offline" });
    } else if (att.role === "browser") {
      const room = await this.getRoom();
      const phone = this.phoneSocket();
      if (room && room.pending && room.pending.bid === att.bid) {
        room.pending = null;
        await this.putRoom(room);
        if (phone) safeSend(phone, { t: "join_cancelled" });
      }
      if (att.state === "active" && !this.activeBrowser() && phone) safeSend(phone, { t: "browser_left" });
    }
  }

  async webSocketError(ws) { await this.webSocketClose(ws, 1011); }
}
