import { test } from "node:test";
import assert from "node:assert/strict";
import { lexical } from "../src/core.js";
const v = (u) => lexical(u).verdict;
test("official domains", () => { for (const d of ["metamask.io", "app.uniswap.org", "phantom.app", "jup.ag"]) assert.equal(v(d), "official"); });
test("lookalikes and typosquats are dangerous", () => { for (const d of ["phantorn.app", "0pensea.io", "ledgerr.com", "xn--metamsk-3ya.io", "https://metamask-wallet-sync.vercel.app/restore"]) assert.equal(v(d), "dangerous", d); });
test("same name other TLD is only caution", () => { assert.equal(v("uniswap.com"), "caution"); });
test("unrelated domains have no flags", () => { for (const d of ["example.com", "github.com"]) assert.equal(v(d), "no_red_flags"); });
test("rejects IPs and localhost", () => { assert.ok(lexical("127.0.0.1").error); assert.ok(lexical("http://localhost/x").error); });
