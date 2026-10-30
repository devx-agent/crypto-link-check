// Minimal stateless MCP (Streamable HTTP, JSON responses) for the free lexical check.
import { lexical } from "./core.js";
const TOOLS = [
  { name: "check_crypto_link", description: "Free, read-only, no network fetch: before connecting a wallet or signing, check a URL/domain for crypto phishing signs (lookalike or typosquat of ~60 wallets/exchanges/dapps, punycode, free hosting, bait words). Returns verdict official | no_red_flags | caution | suspicious | dangerous, plus a link to the paid full check (0.005 USDC via x402: domain age, DNS, redirects, page scan for seed-phrase prompts).",
    inputSchema: { type: "object", properties: { url: { type: "string", description: "URL or bare domain" } }, required: ["url"] }, annotations: { readOnlyHint: true, openWorldHint: false } },
  { name: "full_report_info", description: "How to buy the full link check via x402. Does not pay.", inputSchema: { type: "object", properties: {} }, annotations: { readOnlyHint: true } },
];
const ok = (id, result) => ({ jsonrpc: "2.0", id, result });
const err = (id, code, message) => ({ jsonrpc: "2.0", id, error: { code, message } });
async function handle(m, origin) {
  const { id, method, params } = m || {};
  if (id === undefined || id === null) return null;
  if (method === "initialize") return ok(id, { protocolVersion: (params && params.protocolVersion) || "2025-06-18", capabilities: { tools: { listChanged: false } }, serverInfo: { name: "devx-crypto-link-check", version: "1.0.0" }, instructions: "Check crypto links for phishing before connecting a wallet. Read-only; never asks for keys." });
  if (method === "ping") return ok(id, {});
  if (method === "tools/list") return ok(id, { tools: TOOLS });
  if (method === "tools/call") {
    const name = params && params.name, a = (params && params.arguments) || {};
    if (name === "full_report_info") return ok(id, { content: [{ type: "text", text: `GET ${origin}/v1/check?url=...[&url=...] (1-10 URLs) answers HTTP 402 with an x402 v2 PAYMENT-REQUIRED header: exact, eip155:8453, USDC, 5000 units = 0.005 USDC. Settled only after the report is produced. Docs ${origin}/openapi.json. Humans can pay in the browser at ${origin}/` }] });
    if (name === "check_crypto_link") {
      const r = lexical(a.url || ""); if (r.error) return ok(id, { isError: true, content: [{ type: "text", text: r.error }] });
      r.full_report = `${origin}/v1/check?url=${encodeURIComponent(r.url)}`; r.full_report_price_usdc = 0.005;
      const lines = r.findings.filter((f) => f.level !== "info").map((f) => "- " + f.message);
      return ok(id, { content: [{ type: "text", text: `Verdict: ${r.verdict} for ${r.host}${r.host_unicode !== r.host ? " (shown as " + r.host_unicode + ")" : ""}.\n${lines.join("\n") || "No lexical red flags."}\nFull check (domain age, redirects, page scan): ${r.full_report} (0.005 USDC, x402).\n\n${JSON.stringify(r)}` }], structuredContent: r });
    }
    return err(id, -32602, "unknown tool");
  }
  return err(id, -32601, "method not found");
}
export async function mcp(req, origin) {
  const H = { "content-type": "application/json", "access-control-allow-origin": "*", "access-control-allow-headers": "*", "access-control-expose-headers": "mcp-session-id" };
  if (req.method === "GET") return new Response(JSON.stringify({ name: "devx-crypto-link-check", transport: "streamable-http (POST JSON-RPC)", tools: TOOLS.map((t) => t.name) }), { status: 200, headers: H });
  if (req.method !== "POST") return new Response(null, { status: 405, headers: H });
  let body; try { body = await req.json(); } catch { return new Response(JSON.stringify(err(null, -32700, "parse error")), { status: 400, headers: H }); }
  if (Array.isArray(body)) { const out = (await Promise.all(body.map((m) => handle(m, origin)))).filter(Boolean); return out.length ? new Response(JSON.stringify(out), { headers: H }) : new Response(null, { status: 202, headers: H }); }
  const r = await handle(body, origin);
  return r ? new Response(JSON.stringify(r), { headers: H }) : new Response(null, { status: 202, headers: H });
}
