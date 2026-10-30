import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { lexical } from "./core.js";
export const DEFAULT_BASE = "https://crypto-link-check.nextill-pos.workers.dev";
export const VERSION = "1.1.0";
export function summarize(r) {
  const lines = r.findings.filter((f) => f.level !== "info").map((f) => `  [${f.level}] ${f.message}`);
  return `verdict: ${r.verdict}  ${r.host}${r.host_unicode !== r.host ? " (displays as " + r.host_unicode + ")" : ""}\n${lines.join("\n") || "  no lexical red flags"}`;
}
const VERDICTS = ["official", "no_red_flags", "caution", "suspicious", "dangerous"];
const finding = z.object({ level: z.enum(["info", "warn", "danger"]), code: z.string(), message: z.string() }).passthrough();
const RO = { readOnlyHint: true, destructiveHint: false, idempotentHint: true };

export function createServer(options = {}) {
  const base = options.baseUrl || DEFAULT_BASE;
  const server = new McpServer({ name: "devx-link-check", version: VERSION }, {
    instructions: "Use check_crypto_link before opening a link to connect a wallet, sign a message or type a seed phrase: it says whether the domain is an official wallet/exchange/dapp domain or a lookalike. It runs locally, makes no network requests, never asks for keys and cannot move funds. Verdicts are heuristics, not guarantees. full_report_info only describes the optional paid hosted check; it does not pay.",
  });

  server.registerTool("check_crypto_link", {
    title: "Check a crypto link for phishing",
    description: [
      "Checks one URL or domain for signs of crypto phishing and tells you whether it belongs to a known wallet, exchange or dapp.",
      "Use it before an agent or user opens a link to connect a wallet, sign a message or approve a token, for example a link from an email, DM, ad, search result or support chat.",
      "It runs locally and offline. It makes no network request, does not visit the page, and does not ask for keys. It compares the hostname with a hand-curated list of official domains for about 60 brands and flags lookalike characters (0/o, rn/m, Cyrillic), typosquats, punycode, free hosting and bait words such as 'claim', 'airdrop' or 'sync'.",
      "Returns: verdict (official = on the official list; no_red_flags = nothing found, which is not proof of safety; caution = one warning, such as the brand name on a different TLD; suspicious = two or more warnings; dangerous = impersonation or lookalike), the parsed host and its Unicode form, the official brand it matches or the brand it seems to imitate, and a list of findings. Each finding has a level, code and message.",
      "It does not check domain age, DNS, redirects or page content. For those, see full_report_info (a paid hosted check). Unknown brands are not covered.",
    ].join(" "),
    inputSchema: {
      url: z.string().min(3).max(2048).describe("The link to check: a full URL (https://phantom.app/download) or a bare domain (phantom.app). http(s) only; a missing scheme is treated as https. Public domain names only (no IP addresses or localhost). The hostname and the http/https scheme are judged; the path and query are not analyzed."),
    },
    outputSchema: {
      input: z.string(), url: z.string().describe("normalized URL"), host: z.string().describe("hostname as ASCII/punycode"),
      host_unicode: z.string().describe("hostname as it displays to users"), registrable_domain: z.string().nullable(),
      official_brand: z.string().nullable().describe("brand whose official list contains this domain, else null"),
      impersonation_suspect: z.string().nullable().describe("brand this domain seems to imitate, else null"),
      verdict: z.enum(VERDICTS), findings: z.array(finding),
      full_report: z.string().describe("URL of the paid hosted check for this link"), full_report_price_usdc: z.number(),
    },
    annotations: { ...RO, openWorldHint: false },
  }, async ({ url }) => {
    const r = lexical(url);
    if (r.error) return { isError: true, content: [{ type: "text", text: r.error }] };
    r.full_report = `${base}/v1/check?url=${encodeURIComponent(r.url)}`; r.full_report_price_usdc = 0.005;
    return { structuredContent: r, content: [{ type: "text", text: summarize(r) + "\n\n" + JSON.stringify(r) }] };
  });

  server.registerTool("full_report_info", {
    title: "How to buy the full hosted link check",
    description: [
      "Returns the endpoint, price and payment method of the optional paid hosted check. It does not call the API and does not pay or sign anything.",
      "The paid check covers what check_crypto_link cannot see offline: domain registration age (RDAP), DNS resolution, the redirect chain, and one fetch of the page scanned for seed-phrase prompts and token-approval drainer code. It accepts 1-10 URLs per call for 0.005 USDC on Base via x402.",
      "Use it when check_crypto_link returns no_red_flags or caution for a link that someone is about to trust with a wallet and you want more evidence. If check_crypto_link already says dangerous or official, you usually do not need it.",
      "Returns: method, url_template, price_usdc, network, asset, protocol, max_urls, settles and docs.",
    ].join(" "),
    inputSchema: {},
    outputSchema: { method: z.string(), url_template: z.string(), price_usdc: z.number(), network: z.string(), asset: z.string(), protocol: z.string(), max_urls: z.number(), settles: z.string(), docs: z.string() },
    annotations: { ...RO, openWorldHint: false },
  }, async () => {
    const info = { method: "GET", url_template: `${base}/v1/check?url=<url>[&url=<url2>...]`, price_usdc: 0.005, network: "eip155:8453 (Base)", asset: "USDC", protocol: "x402 v2 exact (HTTP 402 with a PAYMENT-REQUIRED header; any x402 client can pay)", max_urls: 10, settles: "only after the report is produced", docs: `${base}/openapi.json` };
    return { structuredContent: info, content: [{ type: "text", text: JSON.stringify(info) }] };
  });
  return server;
}
