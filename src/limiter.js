import { DurableObject } from "cloudflare:workers";

// Fixed-window counter. One instance per "<bucket>:<ip>" name.
export class Limiter extends DurableObject {
  async fetch(request) {
    const { limit, windowSec } = await request.json();
    const now = Date.now();
    let w = (await this.ctx.storage.get("w")) || { start: now, count: 0 };
    if (now - w.start > windowSec * 1000) w = { start: now, count: 0 };
    w.count++;
    await this.ctx.storage.put("w", w);
    if ((await this.ctx.storage.getAlarm()) === null) {
      await this.ctx.storage.setAlarm(w.start + windowSec * 1000 + 1000);
    }
    return Response.json({ ok: w.count <= limit });
  }
  async alarm() { await this.ctx.storage.deleteAll(); }
}
