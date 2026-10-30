#!/usr/bin/env node
import { lexical } from "../src/core.js";
const args = process.argv.slice(2);
if (args[0] === "mcp") {
  const { createServer } = await import("../src/mcp.js");
  const { StdioServerTransport } = await import("@modelcontextprotocol/sdk/server/stdio.js");
  await createServer({ baseUrl: process.env.LINK_CHECK_URL || undefined }).connect(new StdioServerTransport());
} else if (!args.length || args[0] === "-h" || args[0] === "--help") {
  process.stdout.write("Usage:\n  devx-link-check <url-or-domain> [more...] [--json]   offline crypto phishing / lookalike check\n  devx-link-check mcp                                 run as an MCP server (stdio)\nExit code: 0 official/no red flags, 2 caution/suspicious/dangerous, 1 error. Never asks for keys.\n");
} else {
  const { summarize } = await import("../src/mcp.js");
  const json = args.includes("--json"); let code = 0;
  for (const a of args.filter((x) => x !== "--json")) {
    const r = lexical(a);
    if (r.error) { process.stderr.write(`${a}: ${r.error}\n`); code = code || 1; continue; }
    process.stdout.write((json ? JSON.stringify(r, null, 2) : summarize(r)) + "\n");
    if (!["official", "no_red_flags"].includes(r.verdict)) code = 2;
  }
  process.exitCode = code;
}
