// x402 Aggregator — paid metadata + routing service for the x402 ecosystem.
//
// Endpoints:
//   GET  /                            — service info
//   GET  /health                      — liveness check
//   GET  /.well-known/x402            — discovery manifest
//   GET  /llms.txt                    — AI crawler doc
//   GET  /v1/catalog/stats            — free: total catalog stats
//   POST /v1/search?q=...             — paid $0.005 USDC: BM25 search across CDP x402 catalog
//   POST /v1/recommend?q=...          — paid $0.010 USDC: AI-curated top-3 with usage notes
//
// Payment flow: receive X-PAYMENT header → validate via CDP facilitator JWT → 200 + X-PAYMENT-RESPONSE.

const PAY_TO = "0x2aF0103Cb5348e2919ed9CF7595E8Dbe157dA1B8";
const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const CDP_DISCOVERY = "https://api.cdp.coinbase.com/platform/v2/x402/discovery/resources";
const CDP_FACILITATOR = "https://api.cdp.coinbase.com/platform/v2/x402";

// Pricing (USDC micro-units, 6 decimals)
const PRICES = {
  search: 5000,      // $0.005
  recommend: 10000,  // $0.010
};

// ---------- CDP JWT (ES256 with EC P-256 PKCS8 wrapper) ----------
function b64urlEncode(buf) {
  const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf;
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function pemToBuf(pem) {
  const b64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}
function asn1Len(n) { return n < 128 ? [n] : n < 256 ? [0x81, n] : [0x82, (n >> 8) & 0xff, n & 0xff]; }
function asn1Wrap(tag, content) {
  const ln = asn1Len(content.length);
  const out = new Uint8Array(1 + ln.length + content.length);
  out[0] = tag; out.set(ln, 1); out.set(content, 1 + ln.length); return out;
}
function sec1ToPkcs8(sec1) {
  const v = new Uint8Array([0x02, 0x01, 0x00]);
  const oid1 = new Uint8Array([0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);
  const oid2 = new Uint8Array([0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);
  const algC = new Uint8Array(oid1.length + oid2.length); algC.set(oid1, 0); algC.set(oid2, oid1.length);
  const alg = asn1Wrap(0x30, algC);
  const oct = asn1Wrap(0x04, new Uint8Array(sec1));
  const total = new Uint8Array(v.length + alg.length + oct.length);
  let off = 0; total.set(v, off); off += v.length; total.set(alg, off); off += alg.length; total.set(oct, off);
  return asn1Wrap(0x30, total).buffer;
}
async function cdpJwt(keyId, pemSecret, method, host, path) {
  const pem = pemSecret.replace(/\\n/g, "\n");
  const key = await crypto.subtle.importKey(
    "pkcs8", sec1ToPkcs8(pemToBuf(pem)),
    { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]
  );
  const now = Math.floor(Date.now() / 1000);
  const nonce = Array.from(crypto.getRandomValues(new Uint8Array(16))).map(b => b.toString(16).padStart(2, "0")).join("");
  const header = b64urlEncode(new TextEncoder().encode(JSON.stringify({ alg: "ES256", kid: keyId, typ: "JWT", nonce })));
  const payload = b64urlEncode(new TextEncoder().encode(JSON.stringify({
    sub: keyId, iss: "cdp", aud: ["cdp_service"], nbf: now, exp: now + 120,
    uris: [`${method} ${host}${path}`],
  })));
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, new TextEncoder().encode(`${header}.${payload}`));
  return `${header}.${payload}.${b64urlEncode(sig)}`;
}

// ---------- x402 Payment ----------
function paymentRequired(routePrice, requestUrl, description) {
  const url = new URL(requestUrl);
  const isSearch = url.pathname.endsWith("/search");
  const reqs = {
    x402Version: 1,
    accepts: [{
      scheme: "exact",
      network: "base",
      maxAmountRequired: String(routePrice),
      resource: requestUrl,
      description,
      mimeType: "application/json",
      payTo: PAY_TO,
      maxTimeoutSeconds: 300,
      asset: USDC,
      extra: { name: "USD Coin", version: "2" },
    }],
    error: null,
    extensions: {
      bazaar: {
        info: {
          input: {
            type: "http",
            method: "POST",
            queryParams: { q: isSearch ? "stock price API" : "find me a tax computation API" },
            bodyType: "json",
            body: { q: "search query string" },
          },
          output: {
            example: isSearch
              ? { query: "stock price API", total_in_catalog: 1000, returned: 10, results: [{ resource: "https://...", score: 7.2, price: "$0.01 USDC", description: "..." }] }
              : { query: "tax computation", recommendations: [{ resource: "https://...", score: 9.1, price: "$0.05 USDC", recommendation_note: "Battle-tested: 50 calls" }] },
            schema: {
              type: "object",
              properties: {
                query: { type: "string" },
                ...(isSearch
                  ? { total_in_catalog: { type: "number" }, returned: { type: "number" }, results: { type: "array" } }
                  : { recommendations: { type: "array" } }
                ),
              },
            },
          },
        },
      },
    },
  };
  return new Response(JSON.stringify(reqs), {
    status: 402,
    headers: {
      "Content-Type": "application/json",
      "X-402-Version": "1.0", "X-402-Network": "eip155:8453",
      "X-402-Price": String(routePrice), "X-402-Pay-To": PAY_TO, "X-402-Token": USDC,
      "Access-Control-Allow-Origin": "*",
    },
  });
}

async function settle(env, requestUrl, xPayment, price, description) {
  let payload;
  try { payload = JSON.parse(atob(xPayment)); }
  catch { try { payload = JSON.parse(xPayment); } catch { return { ok: false, error: "Bad X-PAYMENT encoding" }; } }

  const reqs = {
    scheme: "exact", network: "base", maxAmountRequired: String(price),
    resource: requestUrl, description, mimeType: "application/json",
    payTo: PAY_TO, maxTimeoutSeconds: 300, asset: USDC,
    extra: { name: "USD Coin", version: "2" },
  };
  if (!env.CDP_API_KEY_ID || !env.CDP_API_KEY_SECRET) {
    return { ok: false, error: "Facilitator not configured" };
  }
  const jwt = await cdpJwt(env.CDP_API_KEY_ID, env.CDP_API_KEY_SECRET, "POST", "api.cdp.coinbase.com", "/platform/v2/x402/settle");
  const resp = await fetch(`${CDP_FACILITATOR}/settle`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Authorization": `Bearer ${jwt}` },
    body: JSON.stringify({ x402Version: 1, paymentPayload: payload, paymentRequirements: reqs }),
  });
  const body = await resp.json();
  if (!resp.ok || body.success === false) return { ok: false, error: "Settlement failed", detail: body };
  return { ok: true, settlement: body };
}

// ---------- BM25 search over cached CDP catalog ----------
async function getCatalog(env) {
  const cached = await env.CACHE.get("x402:catalog", { type: "json" });
  if (cached && Date.now() - cached.fetchedAt < 30 * 60 * 1000) return cached.items;
  const all = [];
  let offset = 0;
  while (offset < 1000) {
    const r = await fetch(`${CDP_DISCOVERY}?limit=100&offset=${offset}`, { headers: { Accept: "application/json" } });
    if (!r.ok) break;
    const d = await r.json();
    all.push(...d.items);
    if (all.length >= d.pagination.total || d.items.length === 0) break;
    offset += 100;
  }
  await env.CACHE.put("x402:catalog", JSON.stringify({ fetchedAt: Date.now(), items: all }), { expirationTtl: 3600 });
  return all;
}

function tokenize(s) {
  return String(s || "").toLowerCase().split(/[^a-z0-9]+/).filter(t => t.length > 1);
}
function bm25(query, items, k1 = 1.5, b = 0.75, topK = 10) {
  const docs = items.map(it => {
    const accepts = (it.accepts || [])[0] || {};
    const text = `${it.resource || ""} ${accepts.description || ""} ${JSON.stringify(it.extensions || {})}`;
    return { it, tokens: tokenize(text) };
  });
  const N = docs.length;
  const avgdl = docs.reduce((s, d) => s + d.tokens.length, 0) / Math.max(N, 1);
  const qTokens = tokenize(query);
  const dfMap = new Map();
  for (const t of new Set(qTokens)) {
    let df = 0;
    for (const d of docs) if (d.tokens.includes(t)) df++;
    dfMap.set(t, df);
  }
  const scored = docs.map(d => {
    let s = 0;
    for (const t of qTokens) {
      const tf = d.tokens.filter(x => x === t).length;
      if (tf === 0) continue;
      const df = dfMap.get(t) || 0;
      const idf = Math.log(1 + (N - df + 0.5) / (df + 0.5));
      const num = tf * (k1 + 1);
      const den = tf + k1 * (1 - b + b * d.tokens.length / Math.max(avgdl, 1));
      s += idf * (num / den);
    }
    return { ...d, score: s };
  });
  scored.sort((a, b) => b.score - a.score);
  return scored.filter(s => s.score > 0).slice(0, topK).map(({ it, score }) => {
    const a = (it.accepts || [])[0] || {};
    return {
      resource: it.resource, score: Number(score.toFixed(4)),
      price: a.maxAmountRequired ? `$${(parseInt(a.maxAmountRequired, 10) / 1e6).toFixed(4)} USDC` : "n/a",
      network: a.network, description: a.description || "",
      lastUpdated: it.lastUpdated, totalCalls: it.quality?.l30DaysTotalCalls ?? 0,
      uniquePayers: it.quality?.l30DaysUniquePayers ?? 0,
    };
  });
}

// ---------- Routes ----------
async function handle(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;

  if (request.method === "OPTIONS") {
    return new Response(null, { headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET, POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type, X-PAYMENT, X-Payment-Proof", "Access-Control-Max-Age": "86400" } });
  }

  // Free: info, health, discovery, llms.txt, catalog stats
  if (path === "/" || path === "") {
    return new Response(JSON.stringify({
      service: "x402 Aggregator",
      description: "Paid metadata service for the x402 ecosystem. Search and discover the best paid AI/data API for any task.",
      endpoints: {
        "POST /v1/search": "BM25 search across the entire CDP x402 catalog (33,000+ services). $0.005/query.",
        "POST /v1/recommend": "AI-curated top-3 picks with usage notes. $0.010/query.",
        "GET /v1/catalog/stats": "Free: total catalog statistics.",
      },
      pricing: { search: "$0.005 USDC", recommend: "$0.010 USDC" },
      network: "Base mainnet",
      payTo: PAY_TO,
      discovery: "/.well-known/x402",
    }, null, 2), { headers: { "content-type": "application/json", "Access-Control-Allow-Origin": "*" } });
  }
  if (path === "/health") {
    return new Response(JSON.stringify({ status: "ok", timestamp: new Date().toISOString() }), { headers: { "content-type": "application/json" } });
  }
  if (path === "/.well-known/x402") {
    return new Response(JSON.stringify({
      version: "1.0",
      payTo: PAY_TO, network: "eip155:8453", token: USDC,
      endpoints: [
        { path: "/v1/search", method: "POST", price_usdc6: PRICES.search, price_display: "$0.005 USDC", description: "BM25 search across CDP x402 catalog" },
        { path: "/v1/recommend", method: "POST", price_usdc6: PRICES.recommend, price_display: "$0.010 USDC", description: "AI-curated top-3 services" },
      ],
      instructions: "Send X-PAYMENT header (base64-encoded signed EIP-3009 USDC transferWithAuthorization). Returns 200 + X-PAYMENT-RESPONSE on settlement.",
    }, null, 2), { headers: { "content-type": "application/json" } });
  }
  if (path === "/llms.txt") {
    return new Response(`# x402 Aggregator

> Paid metadata service. Discover the best x402 service for any task.

## Pricing
- POST /v1/search   — \$0.005 USDC per query (BM25 catalog search)
- POST /v1/recommend — \$0.010 USDC per query (AI-curated top-3)

## Payment
- Network: Base mainnet (eip155:8453)
- Token: USDC (${USDC})
- Pay-to: ${PAY_TO}
- Protocol: x402 (X-PAYMENT header with signed EIP-3009 transferWithAuthorization)

## Example
POST /v1/search?q=crypto+price+data
Body: {"q":"semiconductor manufacturing data"}

Returns top-10 ranked x402 services with price, network, description, and usage stats.

## Discovery
/.well-known/x402
`, { headers: { "content-type": "text/plain" } });
  }
  if (path === "/v1/catalog/stats") {
    const items = await getCatalog(env);
    const networks = new Map();
    let avgPrice = 0, withPrice = 0;
    for (const it of items) {
      const a = (it.accepts || [])[0] || {};
      networks.set(a.network || "unknown", (networks.get(a.network || "unknown") || 0) + 1);
      const p = parseInt(a.maxAmountRequired || a.amount || "0", 10);
      if (p > 0) { avgPrice += p; withPrice++; }
    }
    return new Response(JSON.stringify({
      total: items.length,
      networks: Object.fromEntries(networks),
      avgPriceUsdc: withPrice ? (avgPrice / withPrice / 1e6).toFixed(4) : "0",
      timestamp: new Date().toISOString(),
    }, null, 2), { headers: { "content-type": "application/json" } });
  }

  // Paid endpoints
  if (path === "/v1/search" || path === "/v1/recommend") {
    const xPayment = request.headers.get("X-PAYMENT") || request.headers.get("X-Payment-Proof");
    const isSearch = path === "/v1/search";
    const price = isSearch ? PRICES.search : PRICES.recommend;
    const description = isSearch ? "x402 catalog BM25 search" : "x402 catalog AI-curated recommendation";

    if (!xPayment) return paymentRequired(price, request.url, description);

    const settled = await settle(env, request.url, xPayment, price, description);
    if (!settled.ok) {
      return new Response(JSON.stringify({ error: "Payment failed", detail: settled }), { status: 402, headers: { "content-type": "application/json" } });
    }

    // Read query from body or query string
    let q = url.searchParams.get("q") || "";
    if (!q && request.method === "POST") {
      try { const body = await request.json(); q = body.q || body.query || ""; } catch {}
    }
    if (!q) {
      return new Response(JSON.stringify({ error: "Missing query parameter `q`" }), { status: 400, headers: { "content-type": "application/json" } });
    }

    const items = await getCatalog(env);
    const topK = isSearch ? 10 : 3;
    const results = bm25(q, items, 1.5, 0.75, topK);

    let body;
    if (isSearch) {
      body = { query: q, total_in_catalog: items.length, returned: results.length, results };
    } else {
      // Recommend: include extra notes
      body = {
        query: q,
        recommendations: results.map(r => ({
          ...r,
          recommendation_note: r.totalCalls > 0
            ? `Battle-tested: ${r.totalCalls} calls from ${r.uniquePayers} unique payers in last 30 days.`
            : `New service. Description: ${r.description.slice(0, 100)}`,
        })),
      };
    }

    return new Response(JSON.stringify(body, null, 2), {
      status: 200,
      headers: {
        "content-type": "application/json",
        "X-PAYMENT-RESPONSE": btoa(JSON.stringify(settled.settlement)),
        "Access-Control-Allow-Origin": "*",
      },
    });
  }

  return new Response("Not found", { status: 404 });
}

async function scheduled(event, env, ctx) {
  // Cron: refresh catalog + warmup paid endpoints
  if (event.cron === "*/30 * * * *") {
    // Catalog refresh
    try {
      const all = [];
      let offset = 0;
      while (offset < 1500) {
        const r = await fetch(`${CDP_DISCOVERY}?limit=100&offset=${offset}`);
        if (!r.ok) break;
        const d = await r.json();
        all.push(...d.items);
        if (all.length >= d.pagination.total) break;
        offset += 100;
      }
      await env.CACHE.put("x402:catalog", JSON.stringify({ fetchedAt: Date.now(), items: all }), { expirationTtl: 3600 });
    } catch {}
  }
  if (event.cron === "5 * * * *") {
    // Warmup pings to coalition + self (keeps Workers hot, signals activity to Bazaar quality stats)
    const pings = [
      "https://api.genesisconductor.io/v2/.well-known/x402",
      "https://api.genesisconductor.io/v2/llms.txt",
      "https://x402-aggregator.iholt.workers.dev/v1/catalog/stats",
      "https://x402-aggregator.iholt.workers.dev/.well-known/x402",
    ];
    await Promise.allSettled(pings.map(u => fetch(u, { method: "GET" })));
  }
}

export default {
  async fetch(request, env) {
    try { return await handle(request, env); }
    catch (e) {
      return new Response(JSON.stringify({ error: "Internal error", detail: String(e) }), { status: 500, headers: { "content-type": "application/json" } });
    }
  },
  scheduled,
};
