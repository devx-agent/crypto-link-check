# Crypto Link Check

**Is that MetaMask / Phantom / Ledger / exchange link real?** Check it before you (or your agent) connect a wallet or sign anything.

October 2026 alone brought fake Phantom, Jupiter and Bitget browser extensions, a hijacked NGRAVE push alert that sent users to a seed-phrase page, and exchange phishing mails. AI agents can now trade from exchange accounts and pay for things on their own, so they click links too. This tool gives them (and you) a quick, read-only second opinion.

- **Free, offline:** CLI and MCP server that compare a link with the official domains of ~60 wallets, exchanges and dapps and flag lookalike characters (`0`/`o`, `rn`/`m`, Cyrillic), typosquats, punycode, free hosting and bait words like "claim" or "sync".
- **Free API + remote MCP:** `https://crypto-link-check.nextill-pos.workers.dev`
- **Paid full check (optional, 0.005 USDC via [x402](https://x402.org) on Base):** adds domain registration age (RDAP), DNS, redirect tracing and one fetch of the page scanned for seed-phrase prompts and token-approval drainer code. 1-10 URLs per call.

It never asks for keys or seed phrases. Verdicts are heuristics, not guarantees.

## CLI

```bash
npx devx-link-check phantorn.app metamask.io
# verdict: dangerous  phantorn.app
#   [danger] phantorn.app spells the official phantom.app with lookalike characters ...
# verdict: official  metamask.io
```

Exit code: `0` official / no red flags, `2` caution / suspicious / dangerous, `1` error. `--json` for machine output.

## MCP

Local (stdio), runs offline:

```json
{ "mcpServers": { "crypto-link-check": { "command": "npx", "args": ["-y", "devx-link-check", "mcp"] } } }
```

Remote (streamable HTTP, no key): `https://crypto-link-check.nextill-pos.workers.dev/mcp`

Tools: `check_crypto_link(url)` and `full_report_info()`.

## HTTP API

| Route | Price | What |
|---|---|---|
| `GET /api/basic?url=...` | free | lexical verdict + findings |
| `GET /v1/check?url=...&url=...` | 0.005 USDC (x402 v2 `exact`, `eip155:8453`) | full check, 1-10 URLs |
| `GET /brands.json` | free | the official-domain list we use |
| `GET /openapi.json`, `/.well-known/x402.json` | free | discovery |

The paid route answers `402` with a `PAYMENT-REQUIRED` header; any x402 client can pay. Settlement happens only after the report is produced. Humans can pay from a browser wallet on the [web page](https://crypto-link-check.nextill-pos.workers.dev). Terms: [/terms](https://crypto-link-check.nextill-pos.workers.dev/terms).

Verdicts: `official`, `no_red_flags`, `caution`, `suspicious`, `dangerous`. Same-name-different-TLD domains are only `caution` because the brand may own them.

## Official-domain list

`cli/src/brands.js`. It is curated by hand and incomplete. PRs that add brands or official domains (with a source) are welcome.

## Layout

- `cli/`: npm package `devx-link-check` (CLI + stdio MCP)
- `worker/`: the Cloudflare Worker behind the hosted API

MIT. Made by [DevX](https://madebydevx.com). Contact madebydevx@gmail.com.
