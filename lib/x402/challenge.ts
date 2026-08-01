import { X402Challenge, X402AcceptRequirement } from "./types.js";
import { getX402Config } from "./config.js";

export const TOOL_PRICES_ATOMIC: Record<string, string> = {
  scan_prompt_injection: "5000",      // 0.005 USDT0
  scan_jailbreak_techniques: "10000", // 0.01 USDT0
  scan_data_exfiltration: "15000",    // 0.015 USDT0
  scan_system_leak: "20000",          // 0.02 USDT0
  attest_prompt_safety: "30000",      // 0.03 USDT0
};

export const TOOL_PRICES_HUMAN: Record<string, string> = {
  scan_prompt_injection: "0.005 USDT0",
  scan_jailbreak_techniques: "0.01 USDT0",
  scan_data_exfiltration: "0.015 USDT0",
  scan_system_leak: "0.02 USDT0",
  attest_prompt_safety: "0.03 USDT0",
};

export const FREE_TOOL_NAMES: string[] = [
  "bulwark_capabilities",
  "validate_prompt_input",
  "estimate_cost",
  "verify_bulwark_report",
  "get_artifact",
];

export function createChallenge(toolName: string): X402Challenge {
  const cfg = getX402Config();
  const atomicAmount = TOOL_PRICES_ATOMIC[toolName] || "5000";
  const humanAmount = TOOL_PRICES_HUMAN[toolName] || "0.005 USDT0";

  const acceptReq: X402AcceptRequirement = {
    scheme: "exact",
    network: cfg.chain,
    asset: cfg.asset,
    amount: atomicAmount,
    payTo: cfg.payTo,
    maxTimeoutSeconds: 300,
    extra: {
      name: cfg.domainName,
      version: cfg.domainVersion,
    },
  };

  return {
    x402Version: 2,
    resource: {
      url: `${cfg.publicBaseUrl}/mcp`,
      description: "EVIDIQ Bulwark — prompt injection & LLM input safety guard for autonomous AI agents.",
      mimeType: "application/json",
    },
    accepts: [acceptReq],
    error: `Payment Required for tool '${toolName}'. Costs ${humanAmount}.`,
  };
}

export function encodeChallengeToBase64(challenge: X402Challenge): string {
  const { error, ...headerChallenge } = challenge;
  return Buffer.from(JSON.stringify(headerChallenge)).toString("base64");
}

export function getX402DiscoveryCatalog() {
  const cfg = getX402Config();
  return {
    x402Version: 2,
    resource: {
      url: `${cfg.publicBaseUrl}/mcp`,
      description: "EVIDIQ Bulwark — prompt injection & LLM input safety guard for autonomous AI agents. Free tools (bulwark_capabilities, validate_prompt_input, estimate_cost, verify_bulwark_report, get_artifact) remain free.",
      mimeType: "application/json",
    },
    accepts: [
      {
        scheme: "exact",
        network: cfg.chain,
        asset: cfg.asset,
        amount: "5000",
        payTo: cfg.payTo,
        maxTimeoutSeconds: 300,
        extra: {
          name: cfg.domainName,
          version: cfg.domainVersion,
        },
      },
    ],
    pricing: [
      { tool: "scan_prompt_injection", amount: "5000", usd: 0.005 },
      { tool: "scan_jailbreak_techniques", amount: "10000", usd: 0.01 },
      { tool: "scan_data_exfiltration", amount: "15000", usd: 0.015 },
      { tool: "scan_system_leak", amount: "20000", usd: 0.02 },
      { tool: "attest_prompt_safety", amount: "30000", usd: 0.03 },
      { tool: "bulwark_capabilities", amount: "0", usd: 0, free: true },
      { tool: "validate_prompt_input", amount: "0", usd: 0, free: true },
      { tool: "estimate_cost", amount: "0", usd: 0, free: true },
      { tool: "verify_bulwark_report", amount: "0", usd: 0, free: true },
      { tool: "get_artifact", amount: "0", usd: 0, free: true },
    ],
    guidance: "Before paying, call the free validate_prompt_input tool first; bulwark_capabilities and estimate_cost are also free.",
  };
}
