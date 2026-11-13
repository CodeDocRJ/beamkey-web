import { Room } from "./room.js";
import { Limiter } from "./limiter.js";
import { b64u, normalizeCode, validPub, CODE_ALPHABET } from "../public/proto.js";

export { Room, Limiter };

const ROOM_TTL_SECONDS = 12 * 60 * 60;
const LIMITS = {
  create: { limit: 10, windowSec: 3600 },  // room creations per IP per hour
  join: { limit: 20, windowSec: 600 },     // browser connection attempts per IP per 10 min
};

const json = (obj, status = 200, extra = {}) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store", ...extra },
  });

async function sha256b64u(str) {
  return b64u.enc(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str))));
}

function randomCode() {
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  let s = "";
  for (const b of bytes) s += CODE_ALPHABET[b & 31]; // 256 % 32 == 0 -> uniform
  return s;
}

async function overLimit(env, bucket, ip) {
  const { limit, windowSec } = LIMITS[bucket];
  const stub = env.LIMITER.get(env.LIMITER.idFromName(`${bucket}:${ip}`));
  const r = await stub.fetch("https://limiter/hit", { method: "POST", body: JSON.stringify({ limit, windowSec }) });
  return !(await r.json()).ok;
}

const roomStub = (env, code) => env.ROOMS.get(env.ROOMS.idFromName(code));

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const ip = request.headers.get("cf-connecting-ip") || "local";

    if (path === "/api/health") return json({ ok: true });

    // ---- Phone: create a room (called once per shift / daily) ----
    if (path === "/api/rooms" && request.method === "POST") {
      if (await overLimit(env, "create", ip)) return json({ error: "rate_limited" }, 429);
      let body;
      try { body = await request.json(); } catch { return json({ error: "bad_json" }, 400); }
      if (!validPub(body.phonePub)) return json({ error: "bad_phone_pub" }, 400);

      const phoneToken = b64u.enc(crypto.getRandomValues(new Uint8Array(32)));
      const tokenHash = await sha256b64u(phoneToken);
      for (let i = 0; i < 5; i++) {
        const code = randomCode();
        const r = await roomStub(env, code).fetch("https://room/init", {
          method: "POST",
          body: JSON.stringify({ code, phonePub: body.phonePub, tokenHash, ttl: ROOM_TTL_SECONDS }),
        });
        if (r.status === 201) {
          const { expiresAt } = await r.json();
          return json({ code, phoneToken, expiresAt, ttlSeconds: ROOM_TTL_SECONDS }, 201);
        }
        if (r.status !== 409) return json({ error: "init_failed" }, 500);
      }
      return json({ error: "no_code_available" }, 503);
    }

    // ---- Phone: destroy a room early ----
    let m = path.match(/^\/api\/rooms\/([^/]+)$/);
    if (m && request.method === "DELETE") {
      const code = normalizeCode(m[1]);
      if (!code) return json({ error: "bad_code" }, 400);
      return roomStub(env, code).fetch("https://room/destroy", {
        method: "POST",
        headers: { authorization: request.headers.get("authorization") || "" },
      });
    }

    // ---- WebSockets ----
    m = path.match(/^\/ws\/(phone|browser)\/([^/]+)$/);
    if (m) {
      if (request.headers.get("Upgrade") !== "websocket") return json({ error: "expected_websocket" }, 426);
      const code = normalizeCode(m[2]);
      if (!code) return json({ error: "bad_code" }, 400);
      if (m[1] === "browser") {
        const origin = request.headers.get("Origin");
        if (origin && origin !== url.origin) return json({ error: "bad_origin" }, 403);
        if (await overLimit(env, "join", ip)) return json({ error: "rate_limited" }, 429);
      }
      return roomStub(env, code).fetch(request);
    }

    return json({ error: "not_found" }, 404);
  },
};
