// DevX Crypto Link Check — heuristic phishing / impersonation checks for crypto URLs. Read-only; never asks for keys.
import { BRANDS, TOKENS, SUFFIX2, FREE_HOSTS } from "./brands.js";

const OFFICIAL = new Map(); for (const [b, ds] of Object.entries(BRANDS)) for (const d of ds) OFFICIAL.set(d, b);
// Common homoglyphs / leetspeak folded to ASCII for comparison.
const CONF = { "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "rn": "m", "vv": "w", "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g", "ı": "i", "ӏ": "l", "ɑ": "a", "ο": "o", "ν": "v", "κ": "k", "τ": "t", "ρ": "p" };
export function skeleton(s) { let t = s.toLowerCase().normalize("NFKD").replace(/[\u0300-\u036f]/g, ""); for (const [k, v] of Object.entries(CONF)) t = t.split(k).join(v); return t.replace(/[^a-z0-9]/g, ""); }
function lev(a, b) { if (Math.abs(a.length - b.length) > 3) return 9; const d = Array.from({ length: a.length + 1 }, (_, i) => [i]); for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) for (let j = 1; j <= b.length; j++) { d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1); } return d[a.length][b.length]; }
export function registrable(host) { const l = host.split("."); if (l.length <= 2) return host; const two = l.slice(-2).join("."); return SUFFIX2.has(two) ? l.slice(-3).join(".") : two; }

export function parseTarget(input) {
  let s = String(input || "").trim(); if (!s) return { error: "url required" };
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = "https://" + s;
  let u; try { u = new URL(s); } catch { return { error: "not a valid URL or domain" }; }
  if (!/^https?:$/.test(u.protocol)) return { error: "only http(s) URLs" };
  const host = u.hostname.toLowerCase().replace(/\.$/, "");
  if (!host.includes(".") || /^[\d.]+$/.test(host) || host.includes(":") || /(^|\.)(localhost|local|internal|lan)$/.test(host)) return { error: "public domain names only (no IPs/localhost)" };
  return { url: u.toString(), host, scheme: u.protocol.replace(":", ""), path: u.pathname };
}
// Decode punycode labels (RFC 3492) so we can show what users actually see.
function punyDecode(label) {
  const base = 36, tmin = 1, tmax = 26, skew = 38, damp = 700; let n = 128, i = 0, bias = 72; const input = label.slice(4); const b = input.lastIndexOf("-");
  const out = b > 0 ? [...input.slice(0, b)] : []; let pos = b > 0 ? b + 1 : 0;
  const adapt = (delta, num, first) => { delta = first ? Math.floor(delta / damp) : delta >> 1; delta += Math.floor(delta / num); let k = 0; while (delta > ((base - tmin) * tmax) >> 1) { delta = Math.floor(delta / (base - tmin)); k += base; } return k + Math.floor(((base - tmin + 1) * delta) / (delta + skew)); };
  while (pos < input.length) { const oldi = i; let w = 1; for (let k = base; ; k += base) { const c = input.charCodeAt(pos++); const dg = c - 48 < 10 ? c - 22 : c - 65 < 26 ? c - 65 : c - 97 < 26 ? c - 97 : base; if (dg >= base) throw new Error("bad"); i += dg * w; const t = k <= bias ? tmin : k >= bias + tmax ? tmax : k - bias; if (dg < t) break; w *= base - t; }
    bias = adapt(i - oldi, out.length + 1, oldi === 0); n += Math.floor(i / (out.length + 1)); i %= out.length + 1; out.splice(i++, 0, String.fromCodePoint(n)); }
  return out.join("");
}
export function unicodeHost(host) { return host.split(".").map((l) => { if (!l.startsWith("xn--")) return l; try { return punyDecode(l); } catch { return l; } }).join("."); }

// Free tier: lexical checks only (no network).
export function lexical(input) {
  const t = parseTarget(input); if (t.error) return t;
  const { host } = t; const reg = registrable(host); const f = [];
  const uni = unicodeHost(host); const puny = host.split(".").some((l) => l.startsWith("xn--"));
  const official = OFFICIAL.get(reg) || (OFFICIAL.has(host) ? OFFICIAL.get(host) : null);
  const freeHost = FREE_HOSTS.find((h) => host === h || host.endsWith("." + h)) || null;
  let impersonates = null;
  if (official) f.push({ level: "info", code: "official_domain", message: `${reg} is on our list of official ${official} domains.` });
  else {
    const regLabel = reg.split(".")[0]; const skHost = skeleton(uni.replace("." + reg.split(".").slice(1).join("."), ""));
    const skReg = skeleton(unicodeHost(regLabel));
    for (const [d, b] of OFFICIAL) {
      const lab = d.split(".")[0]; if (lab.length < 4 || d.split(".").length > 2) continue; const sl = skeleton(lab); const dist = lev(skReg, sl);
      if (dist === 0) { impersonates = b; const same = unicodeHost(regLabel) === lab;
        f.push(same ? { level: "warn", code: "same_name_other_tld", message: `${reg} uses the same name as the official ${d} under a different TLD. It may be owned by the brand or by someone else; we do not know.` }
                    : { level: "danger", code: "lookalike_characters", message: `${reg} spells the official ${d} with lookalike characters (e.g. 0 for o, rn for m, non-Latin letters).` }); break; }
      if (lab.length >= 5 && dist <= (lab.length >= 8 ? 2 : 1)) { impersonates = b; f.push({ level: "danger", code: "typosquat", message: `${unicodeHost(reg)} is ${dist} character edit(s) away from the official ${d}.` }); break; }
    }
    if (!impersonates) for (const [b, tok] of Object.entries(TOKENS)) {
      if (skHost.includes(tok)) { impersonates = b; const raw = uni.toLowerCase().replace(/[^a-z0-9]/g, "").includes(tok);
        f.push(raw ? { level: "warn", code: "brand_in_hostname", message: `Hostname contains "${tok}" but ${reg} is not an official ${b} domain (official: ${BRANDS[b].join(", ")}).` }
                   : { level: "danger", code: "homoglyph_brand", message: `Hostname spells "${tok}" with lookalike characters (e.g. rn for m, 0 for o, Cyrillic letters), but ${reg} is not an official ${b} domain.` }); break; }
    }
  }
  if (puny) f.push({ level: impersonates ? "danger" : "warn", code: "punycode", message: `Internationalized hostname: displays as "${uni}". Homoglyph domains are a common phishing trick.` });
  if (freeHost && !official) f.push({ level: impersonates ? "danger" : "info", code: "free_hosting", message: `Hosted on a free/site-builder platform (${freeHost}). Real wallets and exchanges do not run on these.` });
  if (t.scheme === "http") f.push({ level: "warn", code: "no_https", message: "Plain HTTP (no TLS)." });
  if (/(seed|phrase|recover|restore|validate|sync|airdrop|claim|rectif|dappfix|walletconnect|support|helpdesk|verify|secure|unlock|bonus|giveaway|reward|migrat|refund)/.test(skeleton(host))) f.push({ level: "warn", code: "bait_keyword", message: "Hostname uses wording typical of wallet-drainer and seed-phishing sites (claim / airdrop / sync / recover / validate)." });
  const labels = host.split(".").length; if (labels >= 5) f.push({ level: "info", code: "deep_subdomain", message: `Many subdomain levels (${labels}).` });
  return { input: String(input), url: t.url, host, host_unicode: uni, registrable_domain: reg, official_brand: official, impersonation_suspect: impersonates, findings: f, verdict: verdict(f, official) };
}
function verdict(f, official) {
  if (f.some((x) => x.code === "seed_phrase_request") && !official) return "dangerous";
  const d = f.filter((x) => x.level === "danger").length, w = f.filter((x) => x.level === "warn").length;
  if (d >= 1) return "dangerous"; if (official && !w) return "official"; if (w >= 2) return "suspicious"; if (w === 1) return "caution"; return "no_red_flags";
}

async function fetchT(u, opt = {}, ms = 6000) { const c = new AbortController(); const t = setTimeout(() => c.abort(), ms); try { return await fetch(u, { ...opt, signal: c.signal }); } finally { clearTimeout(t); } }
async function rdap(reg) {
  try { const r = await fetchT(`https://rdap.org/domain/${encodeURIComponent(reg)}`, { headers: { accept: "application/rdap+json", "user-agent": "devx-linkcheck/1.0" }, redirect: "follow" }, 7000);
    if (r.status === 404) return { status: "not_found" }; if (!r.ok) return { status: "unavailable" }; const j = await r.json();
    const ev = (a) => (j.events || []).find((e) => e.eventAction === a)?.eventDate || null;
    const reg_ = (j.entities || []).find((e) => (e.roles || []).includes("registrar")); const rn = reg_?.vcardArray?.[1]?.find((v) => v[0] === "fn")?.[3] || null;
    return { status: "ok", created: ev("registration"), updated: ev("last changed"), expires: ev("expiration"), registrar: rn };
  } catch { return { status: "unavailable" }; }
}
async function dns(host) { try { const r = await fetchT(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=A`, { headers: { accept: "application/dns-json" } }, 4000); const j = await r.json(); return { status: j.Status === 0 ? "resolves" : j.Status === 3 ? "nxdomain" : "error", a: (j.Answer || []).filter((x) => x.type === 1).map((x) => x.data).slice(0, 4) }; } catch { return { status: "unavailable" }; } }
const PRIV = /^(10\.|127\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|0\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/;
const SEED = [/(recovery|secret|seed|mnemonic|backup)\s*(phrase|words?|key)/i, /\b(12|24|18)[-\s]?(word|words)\b/i, /enter\s+your\s+(private\s+key|phrase)/i, /import\s+(your\s+)?wallet/i];
const DRAIN = [/setApprovalForAll/i, /\bpermit2\b/i, /increaseAllowance/i, /eth_signTypedData_v4/i, /\bseaport\b/i, /transferFrom\(/i];
async function page(url) {
  let cur = url; const hops = [];
  for (let i = 0; i < 4; i++) {
    let r; try { r = await fetchT(cur, { redirect: "manual", headers: { "user-agent": "Mozilla/5.0 (compatible; devx-linkcheck/1.0; +https://crypto-link-check.nextill-pos.workers.dev)", accept: "text/html,*/*" } }, 7000); } catch { return { status: "unreachable", hops }; }
    if (r.status >= 300 && r.status < 400 && r.headers.get("location")) { const nx = new URL(r.headers.get("location"), cur).toString(); hops.push({ from: cur, to: nx, status: r.status }); const p = parseTarget(nx); if (p.error) return { status: "redirect_blocked", hops }; cur = nx; continue; }
    const ct = r.headers.get("content-type") || ""; let text = "";
    if (/text|html|javascript|json/.test(ct)) { const rd = r.body.getReader(); let got = 0; const parts = []; while (got < 300000) { const { done, value } = await rd.read(); if (done) break; parts.push(value); got += value.length; } try { rd.cancel(); } catch {} text = new TextDecoder().decode(parts.reduce((a, b) => { const c = new Uint8Array(a.length + b.length); c.set(a); c.set(b, a.length); return c; }, new Uint8Array())); }
    const title = (text.match(/<title[^>]*>([^<]{0,200})/i) || [])[1]?.trim() || null;
    const seed = SEED.filter((re) => re.test(text)).map(String); const drain = DRAIN.filter((re) => re.test(text)).map((re) => re.source.replace(/\\b|\\\(/g, ""));
    const inputs = (text.match(/<(input|textarea)\b/gi) || []).length; const pw = (text.match(/type=["']?password/gi) || []).length;
    const walletJs = /window\.ethereum|ethereum\.request|solana\.connect|walletconnect|web3modal|wagmi/i.test(text);
    return { status: r.status, final_url: cur, hops, content_type: ct.split(";")[0], bytes_scanned: text.length, title, seed_phrase_wording: seed.length > 0, seed_patterns: seed.length, drainer_signatures: drain, wallet_connect_code: walletJs, input_fields: inputs, password_fields: pw };
  }
  return { status: "too_many_redirects", hops };
}
// Paid tier: lexical + domain age (RDAP) + DNS + page scan, combined verdict.
export async function full(input) {
  const lx = lexical(input); if (lx.error) return lx;
  const [rd, dn] = await Promise.all([rdap(lx.registrable_domain), dns(lx.host)]);
  const f = [...lx.findings]; let pg = null;
  if (dn.status === "nxdomain") f.push({ level: "info", code: "nxdomain", message: "Hostname does not resolve (taken down or never existed)." });
  if (dn.a && dn.a.some((ip) => PRIV.test(ip))) f.push({ level: "warn", code: "private_ip", message: "Resolves to a private/reserved IP; page not fetched." });
  else if (dn.status === "resolves") pg = await page(lx.url);
  let ageDays = null;
  if (rd.created) { ageDays = Math.floor((Date.now() - Date.parse(rd.created)) / 86400000);
    if (ageDays < 30) f.push({ level: lx.impersonation_suspect ? "danger" : "warn", code: "new_domain", message: `Domain registered ${ageDays} day(s) ago (${rd.created.slice(0, 10)}).` });
    else if (ageDays < 180) f.push({ level: "info", code: "young_domain", message: `Domain is ${ageDays} days old.` });
    else f.push({ level: "info", code: "domain_age", message: `Domain is ${Math.floor(ageDays / 365 * 10) / 10} years old (${rd.created.slice(0, 10)}).` }); }
  else f.push({ level: "info", code: "age_unknown", message: "Registration date not available via RDAP for this TLD." });
  if (pg && pg.hops && pg.hops.length) { const last = parseTarget(pg.final_url || pg.hops.at(-1).to); const lr = registrable(last.host || ""); if (!last.error && lr !== lx.registrable_domain && !(lx.official_brand && OFFICIAL.get(lr) === lx.official_brand)) f.push({ level: "warn", code: "offsite_redirect", message: `Redirects to a different site: ${last.host}.` }); }
  if (pg && pg.seed_phrase_wording && !lx.official_brand) f.push({ level: "danger", code: "seed_phrase_request", message: "Page text asks about a recovery/seed phrase or private key. Legitimate sites never ask you to type it into a web page." });
  if (pg && pg.drainer_signatures && pg.drainer_signatures.length && !lx.official_brand && (lx.impersonation_suspect || (ageDays !== null && ageDays < 30))) f.push({ level: "danger", code: "approval_drain_code", message: `Page code uses token-approval/signature calls (${pg.drainer_signatures.join(", ")}) on an impersonating or brand-new domain: typical wallet-drainer kit.` });
  else if (pg && pg.wallet_connect_code && lx.impersonation_suspect) f.push({ level: "warn", code: "wallet_connect_on_lookalike", message: "Page wants a wallet connection while impersonating a brand." });
  const out = { ...lx, findings: f, domain: { rdap: rd, age_days: ageDays }, dns: dn, page: pg };
  out.verdict = verdict(f, lx.official_brand);
  out.advice = out.verdict === "dangerous" ? "Do not connect a wallet, sign anything or type a seed phrase here. If you already did, move funds to a new wallet created on a clean device and revoke approvals." :
    out.verdict === "suspicious" ? "Several red flags. Navigate to the brand's official site yourself instead of following this link." :
    out.verdict === "caution" ? "One red flag. Double-check the exact domain before connecting a wallet." :
    out.verdict === "official" ? "Domain is on our official list. Still check you typed it yourself and never type your seed phrase into any website." : "No red flags found by these heuristics. That is not proof the site is safe.";
  out.checked_at = new Date().toISOString();
  out.disclaimer = "Heuristic, read-only checks (domain lexical analysis, RDAP, DNS, a single page fetch). Not a guarantee. This service never asks for keys or seed phrases.";
  return out;
}
