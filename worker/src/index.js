import { lexical, full } from "./core.js";
import { BRANDS } from "./brands.js";
import PAGE from "./page.html";
import EXPLAINER from "./explainer.html";
import { mcp } from "./mcp.js";

const VERSION = "1.0.0";
const SERVICE = "DevX Crypto Link Check";
const PAY_TO = "0xB3cDDccEe6B150c8efFD55B961afc0Ecefe7f247";
const FACILITATOR = "https://facilitator.payai.network";
const USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const PRICE = "5000"; // 0.005 USDC per report (1-10 URLs)
const ROUTE = "/v1/check";
const MAX = 10;
const DESC = "Phishing / impersonation check for crypto links before an agent or person connects a wallet or signs: brand lookalikes & typosquats of " + Object.keys(BRANDS).length + " wallets/exchanges/dapps, punycode, domain age (RDAP), DNS, redirects, and a page scan for seed-phrase prompts and approval-drainer code. 1-10 URLs per call.";
const enc = new TextEncoder();
const b64 = (o) => btoa(String.fromCharCode(...enc.encode(JSON.stringify(o))));
const unb64 = (s) => JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(s.trim()), (c) => c.charCodeAt(0))));
const EX_URL = "https://metamask-wallet-sync.vercel.app/restore";
const EXAMPLE = { url: EX_URL, verdict: "dangerous", impersonation_suspect: "metamask", findings: [{ level: "warn", code: "brand_in_hostname" }, { level: "danger", code: "free_hosting" }, { level: "warn", code: "bait_keyword" }], domain: { age_days: null }, page: { seed_phrase_wording: true }, advice: "..." };

function requirements() { return { scheme: "exact", network: "eip155:8453", amount: PRICE, asset: USDC_BASE, payTo: PAY_TO, maxTimeoutSeconds: 120, extra: { name: "USD Coin", version: "2" } }; }
function advertised(resUrl) { return { ...requirements(), maxAmountRequired: PRICE, resource: resUrl, description: DESC, mimeType: "application/json" }; }
function paymentRequired(origin, error, resUrl) {
  resUrl = resUrl || origin + ROUTE;
  return { x402Version: 2, error: error || "PAYMENT-SIGNATURE header is required",
    resource: { url: resUrl, description: DESC, mimeType: "application/json", serviceName: SERVICE, tags: ["security", "phishing", "wallet", "agents", "x402", "url-check"] },
    accepts: [advertised(resUrl)],
    extensions: { bazaar: { info: { input: { type: "http", method: "GET", queryParams: { url: EX_URL } }, output: { type: "json", example: EXAMPLE } },
      schema: { $schema: "https://json-schema.org/draft/2020-12/schema", type: "object", properties: { input: { type: "object", properties: { type: { type: "string", const: "http" }, method: { type: "string", enum: ["GET"] }, queryParams: { type: "object", properties: { url: { type: "string", description: "URL or domain to check; repeat the url parameter for up to 10" } }, required: ["url"] } }, required: ["type", "method"] }, output: { type: "object" } }, required: ["input"] } } } };
}
const H = { "content-type": "application/json", "access-control-allow-origin": "*", "access-control-expose-headers": "PAYMENT-REQUIRED, PAYMENT-RESPONSE" };
const J = (o, status = 200, h = {}) => new Response(JSON.stringify(o, null, 2), { status, headers: { ...H, ...h } });
async function facil(op, body) { const r = await fetch(`${FACILITATOR}/${op}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }); try { return await r.json(); } catch { return {}; } }
function parseUrls(sp) {
  const list = [...new Set(sp.getAll("url").map((s) => s.trim()).filter(Boolean))];
  if (!list.length) return { error: "url query parameter required (repeat ?url=...&url=... for up to 10)" };
  if (list.length > MAX) return { error: `max ${MAX} URLs per call` };
  for (const u of list) { const r = lexical(u); if (r.error) return { error: `${u}: ${r.error}` }; }
  return { list };
}
const TERMS = `${SERVICE} - Terms of Service (v${VERSION}, effective 2026-10-30)
Operator: DevX / Made by DevX (madebydevx.com), contact madebydevx@gmail.com.
1. Service. Heuristic checks of a URL or domain for crypto phishing and brand impersonation. GET /api/basic?url=... (free) runs lexical checks only (official-domain list, lookalikes, typosquats, punycode, free hosting, bait words). GET ${ROUTE}?url=...[&url=...] (paid, 1-${MAX} URLs) adds domain registration date via RDAP, DNS, redirect tracing and a single fetch of the page (first ~300 KB) scanned for seed-phrase prompts and token-approval code, with a combined verdict. We never ask for, receive or store seed phrases or private keys.
2. Price. 0.005 USDC per paid call, x402 v2 "exact" on Base (eip155:8453), paid to ${PAY_TO}, settled through ${FACILITATOR}. In the browser you sign an EIP-3009 USDC authorization for exactly that amount; gas is paid by the facilitator.
3. Not charged on error. Payment is settled only after the report is produced. Invalid input or an internal error returns an error and the authorization is not settled.
4. Refunds. If you were charged but got no report, email madebydevx@gmail.com with the Base tx hash within 30 days; verified cases are refunded in USDC on Base to the paying address.
5. Not a guarantee. Verdicts are heuristics. "no_red_flags" does not prove a site is safe and "dangerous" does not prove it is malicious. The official-domain list is curated by hand and not exhaustive. Always type wallet and exchange addresses yourself.
6. Data. We do not store checked URLs beyond Cloudflare's standard request logs. Our fetcher identifies itself as devx-linkcheck and fetches only the URL you submit (plus up to 3 redirects), never private IPs.
7. Changes. Material changes bump the version; the price in the live 402 response is authoritative.`;
function docs(origin) {
  return { openapi: "3.1.0", info: { title: SERVICE, version: VERSION, description: DESC, termsOfService: origin + "/terms", contact: { name: "DevX", email: "madebydevx@gmail.com", url: "https://madebydevx.com" } },
    servers: [{ url: origin }],
    paths: {
      "/api/basic": { get: { summary: "Free: lexical phishing/impersonation check for one URL or domain", parameters: [{ name: "url", in: "query", required: true, schema: { type: "string" } }], responses: { 200: { description: "verdict + findings" } } } },
      [ROUTE]: { get: { summary: "Paid (0.005 USDC, x402): full link check for 1-10 URLs (RDAP age, DNS, redirects, page scan)", parameters: [{ name: "url", in: "query", required: true, schema: { type: "string" }, description: "URL or domain; repeat for up to 10" }],
        "x-payment-info": { protocol: "x402", x402Version: 2, scheme: "exact", network: "eip155:8453", asset: USDC_BASE, amount: PRICE, price_usd: 0.005, payTo: PAY_TO, facilitator: FACILITATOR },
        responses: { 200: { description: "reports" }, 402: { description: "Payment required (PAYMENT-REQUIRED header, x402 v2)" } } } } } };
}
export default {
  async fetch(req) {
    const url = new URL(req.url), origin = url.origin, p = url.pathname;
    if (req.method === "OPTIONS") return new Response(null, { headers: { ...H, "access-control-allow-headers": "*", "access-control-allow-methods": "GET, HEAD, POST, OPTIONS" } });
    if (p === "/") return new Response(PAGE.replaceAll("__PAYTO__", PAY_TO), { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "public, max-age=300" } });
    if (p === "/index.json") return J({ service: SERVICE, version: VERSION, by: "Made by DevX (madebydevx.com)", free: origin + "/api/basic?url=...", paid: origin + ROUTE + "?url=...", price_usdc: 0.005, protocol: "x402 v2 exact, USDC on Base", payTo: PAY_TO, mcp: origin + "/mcp", docs: origin + "/openapi.json", terms: origin + "/terms", description: DESC });
    if (p === "/how-to-spot-fake-crypto-links" || p === "/how-to-spot-fake-crypto-links/") return new Response(EXPLAINER, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "public, max-age=3600" } });
    if (p === "/robots.txt") return new Response("User-agent: *\nAllow: /\nSitemap: https://crypto-link-check.nextill-pos.workers.dev/sitemap.xml\n", { headers: { "content-type": "text/plain" } });
    if (p === "/sitemap.xml") return new Response('<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://crypto-link-check.nextill-pos.workers.dev/</loc><lastmod>2026-10-30</lastmod></url><url><loc>https://crypto-link-check.nextill-pos.workers.dev/how-to-spot-fake-crypto-links</loc><lastmod>2026-10-30</lastmod></url></urlset>', { headers: { "content-type": "application/xml" } });
    if (p === "/llms.txt") return new Response(`# DevX Crypto Link Check
> Free check of crypto links for lookalike, typosquat and punycode domains of ~60 wallets, exchanges and dapps. Paid full check 0.005 USDC via x402 on Base.
- Explainer: https://crypto-link-check.nextill-pos.workers.dev/how-to-spot-fake-crypto-links
- Free API: GET /api/basic?url=...
- Paid API (x402): GET /v1/check?url=...&url=...
- MCP: https://crypto-link-check.nextill-pos.workers.dev/mcp
- Brand list: /brands.json
- OpenAPI: /openapi.json
- Source: https://github.com/devx-agent/crypto-link-check
- Related: https://sweeper-check.nextill-pos.workers.dev/what-is-an-eip-7702-sweeper
`, { headers: { "content-type": "text/plain; charset=utf-8" } });
    if (p === "/terms") return new Response(TERMS, { headers: { "content-type": "text/plain; charset=utf-8", "access-control-allow-origin": "*" } });
    if (p === "/openapi.json") return J(docs(origin));
    if (p === "/brands.json") return J({ note: "Official domains we treat as genuine. Curated, not exhaustive. Corrections: madebydevx@gmail.com", brands: BRANDS });
    if (p === "/.well-known/agent-tools-verify.txt") return new Response("atc_WoFrTiIYSQzNZmCO1Ws17ZrcxAmJkCNL\n", { headers: { "content-type": "text/plain" } });
    if (p === "/.well-known/x402") return J({ version: 1, resources: [origin + ROUTE], description: SERVICE });
    if (p === "/.well-known/x402.json") return J({ x402Version: 2, name: SERVICE, provider: "Made by DevX (madebydevx.com)", resources: [{ url: origin + ROUTE, method: "GET", description: DESC, accepts: [requirements()] }] });
    if (p === "/mcp") return mcp(req, origin);
    if (p === "/.well-known/mcp.json" || p === "/.well-known/mcp/server-card.json") return J({ name: "devx-crypto-link-check", description: "Crypto phishing / brand-impersonation link check for agents", url: origin + "/mcp", transport: "streamable-http", tools: ["check_crypto_link", "full_report_info"], provider: "Made by DevX", repository: "https://github.com/devx-agent/crypto-link-check", npm: "devx-link-check" });
    if (p === "/health") return J({ ok: true, version: VERSION });
    if (p === "/api/basic") {
      const r = lexical(url.searchParams.get("url") || ""); if (r.error) return J({ error: r.error }, 400);
      r.full_report = origin + ROUTE + "?url=" + encodeURIComponent(r.url); r.full_report_price_usdc = 0.005; r.note = "Free tier = lexical checks only (no network lookups)."; return J(r);
    }
    if (p !== ROUTE) return J({ error: "not found", see: origin + "/index.json" }, 404);
    if (req.method !== "GET" && req.method !== "HEAD") return J({ error: "use GET" }, 405);
    const pr = paymentRequired(origin, null, origin + ROUTE + url.search);
    const parsed = parseUrls(url.searchParams);
    const sig = req.headers.get("PAYMENT-SIGNATURE") || req.headers.get("X-PAYMENT");
    if (!sig) return J(pr, 402, { "PAYMENT-REQUIRED": b64(pr) });
    if (parsed.error) return J({ error: parsed.error + " (you were not charged)" }, 400);
    let payload; try { payload = unb64(sig); } catch { return J({ ...pr, error: "malformed PAYMENT-SIGNATURE" }, 400, { "PAYMENT-REQUIRED": b64(pr) }); }
    const reqs = requirements(), acc = payload.accepted || {};
    if (payload.x402Version !== 2 || acc.network !== reqs.network || acc.payTo?.toLowerCase() !== PAY_TO.toLowerCase() || acc.amount !== reqs.amount || acc.asset?.toLowerCase() !== USDC_BASE.toLowerCase())
      return J({ ...pr, error: "payment does not match requirements (x402 v2, exact, eip155:8453 USDC 5000)" }, 402, { "PAYMENT-REQUIRED": b64(pr) });
    const v = await facil("verify", { x402Version: 2, paymentPayload: payload, paymentRequirements: reqs });
    if (!v.isValid) return J({ ...pr, error: "payment invalid: " + (v.invalidReason || "unknown") }, 402, { "PAYMENT-REQUIRED": b64(pr) });
    let reports; try { reports = await Promise.all(parsed.list.map(full)); } catch (e) { return J({ error: "internal error, you were not charged" }, 500); }
    const s = await facil("settle", { x402Version: 2, paymentPayload: payload, paymentRequirements: reqs });
    if (!s.success) return J({ ...pr, error: "settlement failed: " + (s.errorReason || "unknown") + " (report withheld, not charged)" }, 402, { "PAYMENT-REQUIRED": b64(pr), "PAYMENT-RESPONSE": b64(s) });
    return J({ service: SERVICE, version: VERSION, count: reports.length, reports, payment: { tx: s.transaction || null, network: s.network || "eip155:8453" } }, 200, { "PAYMENT-RESPONSE": b64(s) });
  },
};
