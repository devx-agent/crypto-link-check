import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { lexical } from "./core.js";
export const DEFAULT_BASE = "https://crypto-link-check.nextill-pos.workers.dev";
export function summarize(r) {
  const lines = r.findings.filter((f) => f.level !== "info").map((f) => `  [${f.level}] ${f.message}`);
  return `verdict: ${r.verdict}  ${r.host}${r.host_unicode !== r.host ? " (displays as " + r.host_unicode + ")" : ""}\n${lines.join("\n") || "  no lexical red flags"}`;
}
export function createServer(options = {}) {
  const base = options.baseUrl || DEFAULT_BASE;
  const server = new McpServer({ name: "devx-link-check", version: "1.0.0" }, { instructions: "Check a crypto link for phishing / brand impersonation before connecting a wallet or signing. Runs locally, read-only, never asks for keys." });
  server.tool("check_crypto_link", "Free, offline: check a URL or domain for crypto phishing signs (lookalike or typosquat of ~60 wallets/exchanges/dapps, punycode, free hosting, bait words). Verdict official | no_red_flags | caution | suspicious | dangerous.",
    { url: z.string().min(3).describe("URL or bare domain") },
    async ({ url }) => { const r = lexical(url); if (r.error) return { isError: true, content: [{ type: "text", text: r.error }] };
      r.full_report = `${base}/v1/check?url=${encodeURIComponent(r.url)}`; r.full_report_price_usdc = 0.005;
      return { content: [{ type: "text", text: summarize(r) + "\n\n" + JSON.stringify(r) }] }; });
  server.tool("full_report_info", "How to get the paid full link check (domain age, DNS, redirects, page scan for seed-phrase prompts) via x402. Does not pay anything.", {},
    async () => ({ content: [{ type: "text", text: `GET ${base}/v1/check?url=...[&url=...] (1-10 URLs) returns HTTP 402 with an x402 v2 PAYMENT-REQUIRED header (exact, eip155:8453 USDC, 5000 units = 0.005 USDC). Settled only after the report is produced. Docs: ${base}/openapi.json` }] }));
  return server;
}
