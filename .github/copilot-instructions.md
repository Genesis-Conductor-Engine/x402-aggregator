# Copilot Instructions — x402 Aggregator

Cloudflare Worker that wraps the CDP x402 catalog with paid BM25 search and AI-curated recommendations.

## Critical files

| Path | Purpose |
|---|---|
| `src/index.js` | Single-file Worker (~400 lines) |
| `wrangler.toml` | Bindings: `CACHE` KV, two crons |

## What this Worker does

| Path | Method | Price | Behavior |
|---|---|---|---|
| `/v1/search` | POST | $0.005 USDC | BM25 over cached CDP catalog (1500 entries) |
| `/v1/recommend` | POST | $0.010 USDC | Top-3 ranked + usage notes |
| `/v1/catalog/stats` | GET | free | Total, networks, avg price |
| `/.well-known/x402` | GET | free | Discovery manifest |
| `/llms.txt` | GET | free | AI crawler doc |

## Crons

- `*/30 * * * *` — refresh CDP catalog cache (writes to KV)
- `5 * * * *` — warmup pings

## Conventions

- **payTo**: `0x2aF0103Cb5348e2919ed9CF7595E8Dbe157dA1B8` (shared with coalition-gateway).
- **Network**: `"base"` for x402 v1, `"eip155:8453"` for catalog metadata only.
- **CDP fetch**: uses `generateCdpJwt()` against `api.cdp.coinbase.com/platform/v2/x402/discovery/resources` (paginates 100 at a time).
- **Cache key**: `cdp:catalog` in KV, TTL = 30 min.

## Things to never do

- Never call CDP `/discovery/resources` from the request path — always read from KV cache.
- Never include the same-account-`.workers.dev` URL in any internal pings (Workers can't fetch their own subdomain).
- Never widen `BATCH_SIZE_N` past 256 for trace events — IWA-020 invariant.

## Deploy

```bash
cd /Users/igorholt/x402-aggregator && npx wrangler deploy
```
