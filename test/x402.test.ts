import { describe, it, expect } from "vitest";
import {
  TOOL_PRICES_ATOMIC,
  TOOL_PRICES_HUMAN,
  createChallenge,
  encodeChallengeToBase64,
  getX402DiscoveryCatalog,
} from "../lib/x402/challenge.js";
import { PAID_TOOLS, isPaidTool } from "../lib/x402/gate.js";

describe("EVIDIQ Bulwark x402 challenge & pricing", () => {
  it("has exactly 5 paid tools with correct atomic amounts", () => {
    expect(Array.from(PAID_TOOLS).sort()).toEqual(
      [
        "scan_prompt_injection",
        "scan_jailbreak_techniques",
        "scan_data_exfiltration",
        "scan_system_leak",
        "attest_prompt_safety",
      ].sort()
    );
    expect(TOOL_PRICES_ATOMIC.scan_prompt_injection).toBe("5000");
    expect(TOOL_PRICES_ATOMIC.scan_jailbreak_techniques).toBe("10000");
    expect(TOOL_PRICES_ATOMIC.scan_data_exfiltration).toBe("15000");
    expect(TOOL_PRICES_ATOMIC.scan_system_leak).toBe("20000");
    expect(TOOL_PRICES_ATOMIC.attest_prompt_safety).toBe("30000");
  });

  it("prices are AssetAmount atomic strings, not USD (§8 runbook)", () => {
    for (const k of Object.keys(TOOL_PRICES_ATOMIC)) {
      expect(typeof TOOL_PRICES_ATOMIC[k]).toBe("string");
      expect(TOOL_PRICES_ATOMIC[k]).toMatch(/^\d+$/);
    }
  });

  it("createChallenge builds a v2 challenge with the right shape", () => {
    const c = createChallenge("scan_prompt_injection");
    expect(c.x402Version).toBe(2);
    expect(c.resource.url).toContain("/mcp");
    expect(c.accepts[0].scheme).toBe("exact");
    expect(c.accepts[0].network).toBe("eip155:196");
    expect(c.accepts[0].asset).toBe("0x779ded0c9e1022225f8e0630b35a9b54be713736");
    expect(c.accepts[0].amount).toBe("5000");
    expect(c.accepts[0].payTo).toBe("0x2a8efe3093278bb4bd3b2d9c7b5ba992ca4fc9b0");
    expect(c.accepts[0].extra).toEqual({ name: "USD₮0", version: "1" });
    expect(c.error).toBeDefined();
  });

  it("encoded challenge header excludes `error` field (§41 trap)", () => {
    const c = createChallenge("attest_prompt_safety");
    const b64 = encodeChallengeToBase64(c);
    const decoded = JSON.parse(Buffer.from(b64, "base64").toString("utf-8"));
    expect(decoded.x402Version).toBe(2);
    expect(decoded.accepts[0].amount).toBe("30000");
    expect(decoded.error).toBeUndefined();
    expect(decoded.accepts[0].extra).toEqual({ name: "USD₮0", version: "1" });
  });

  it("discovery catalog lists all 10 tools with prices", () => {
    const cat = getX402DiscoveryCatalog();
    expect(cat.x402Version).toBe(2);
    expect(cat.pricing).toHaveLength(10);
    expect(cat.pricing.filter((p) => !p.free)).toHaveLength(5);
    expect(cat.pricing.filter((p) => p.free)).toHaveLength(5);
  });

  it("isPaidTool gate matches PAID_TOOLS exactly", () => {
    for (const t of PAID_TOOLS) expect(isPaidTool(t)).toBe(true);
    expect(isPaidTool("bulwark_capabilities")).toBe(false);
    expect(isPaidTool("estimate_cost")).toBe(false);
    expect(isPaidTool("nonexistent_tool")).toBe(false);
  });
});
