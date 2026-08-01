import { createMcpHandler } from "mcp-handler";
import { z } from "zod";
import { runBulwarkEvaluation } from "./lib/bulwark/detector.js";
import {
  createBulwarkReport,
  verifyBulwarkReport,
  hashInput,
  BulwarkReport,
} from "./lib/bulwark/report.js";
import { DEFAULT_POLICY_CONFIG, POLICY_VERSION, ENGINE_VERSION } from "./lib/bulwark/policy.js";
import {
  PATTERN_CATALOG,
  ALL_CATEGORIES,
  TOOL_SCAN_CATEGORIES,
} from "./lib/bulwark/patterns.js";
import {
  TOOL_PRICES_ATOMIC,
  TOOL_PRICES_HUMAN,
  FREE_TOOL_NAMES,
} from "./lib/x402/challenge.js";
import { PAID_TOOLS } from "./lib/x402/gate.js";
import { anchorToOgStorage } from "./lib/og/storage.js";

const ARTIFACT_STORE = new Map<string, BulwarkReport>();

function textResult(value: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(value, null, 2) }] };
}

const BULWARK_INSTRUCTIONS = `EVIDIQ Bulwark — prompt injection & LLM input safety guard for autonomous AI agents.

Use validate_prompt_input before paying. Paid tools scan prompts/retrieved context for direct injection, indirect injection, jailbreak techniques, data-exfiltration payloads, and system-prompt leaks — returning a BLOCK/WARN/ALLOW verdict with signed, 0G-anchored evidence.

Five free tools: bulwark_capabilities, validate_prompt_input, estimate_cost, verify_bulwark_report, get_artifact.
Five x402-paid tools: scan_prompt_injection (0.005 USDT0), scan_jailbreak_techniques (0.01 USDT0), scan_data_exfiltration (0.015 USDT0), scan_system_leak (0.02 USDT0), attest_prompt_safety (0.03 USDT0). Payment settles before work begins.`;

function buildScanInput(prompt: string, context?: string): string {
  return context && context.length > 0 ? `${prompt}\n${context}` : prompt;
}

async function runScan(params: {
  prompt: string;
  context?: string;
  toolName: string;
}) {
  const startTime = Date.now();
  const input = buildScanInput(params.prompt, params.context);
  const categories = TOOL_SCAN_CATEGORIES[params.toolName];
  const evalResult = runBulwarkEvaluation({ input, categories });

  let zeroGAnchorTx: string | undefined;
  let zeroGStorageRoot: string | undefined;
  if (params.toolName === "attest_prompt_safety") {
    const ogRes = await anchorToOgStorage({
      reportDigestHint: evalResult.inputHash,
      policyVersion: POLICY_VERSION,
    });
    if (ogRes.ok) {
      zeroGAnchorTx = ogRes.tx;
      zeroGStorageRoot = ogRes.root;
    }
  }

  const report = await createBulwarkReport({
    input: evalResult.scannedInput,
    inputHash: evalResult.inputHash,
    scanCategories: evalResult.scanCategories,
    trace: evalResult.trace,
    violations: evalResult.violations,
    evaluationQuality: evalResult.evaluationQuality,
    evaluationStartTimeMs: startTime,
    zeroGAnchorTx,
    zeroGStorageRoot,
  });

  ARTIFACT_STORE.set(report.metadata.executionId, report);
  ARTIFACT_STORE.set(report.receipt.reportDigest, report);

  return textResult({
    success: true,
    verdict: report.verdict,
    executionId: report.metadata.executionId,
    evaluationQuality: report.metadata.evaluationQuality,
    report,
  });
}

export const handler = createMcpHandler(
  (server) => {
    // ── PAID 1: scan_prompt_injection (0.005 USDT0) ─────────────────────────
    server.registerTool(
      "scan_prompt_injection",
      {
        title: "Scan for direct & indirect prompt injection",
        description:
          "Scan a prompt and optional retrieved context for direct prompt injection (role hijack, instruction override, delimiter violation) and indirect injection (hidden instructions, tool hijack, encoding smuggle). Costs 0.005 USDT0.",
        inputSchema: {
          prompt: z.string().describe("The prompt / user message to scan."),
          context: z.string().optional().describe("Optional retrieved/RAG context appended to the prompt for indirect-injection scanning."),
        },
      },
      async ({ prompt, context }) => runScan({ prompt, context, toolName: "scan_prompt_injection" })
    );

    // ── PAID 2: scan_jailbreak_techniques (0.01 USDT0) ──────────────────────
    server.registerTool(
      "scan_jailbreak_techniques",
      {
        title: "Scan for known jailbreak technique signatures",
        description:
          "Detect known jailbreak technique signatures (DAN variants, prefix injection, roleplay bypass, credential interleaving). Costs 0.01 USDT0.",
        inputSchema: {
          prompt: z.string().describe("The prompt to scan for jailbreak techniques."),
          context: z.string().optional().describe("Optional retrieved context appended to the prompt."),
        },
      },
      async ({ prompt, context }) => runScan({ prompt, context, toolName: "scan_jailbreak_techniques" })
    );

    // ── PAID 3: scan_data_exfiltration (0.015 USDT0) ────────────────────────
    server.registerTool(
      "scan_data_exfiltration",
      {
        title: "Scan for data-exfiltration payloads",
        description:
          "Detect data exfiltration payloads in prompts/context (URL-based extraction, encoded blobs, tool-call hijack for data theft). Costs 0.015 USDT0.",
        inputSchema: {
          prompt: z.string().describe("The prompt to scan for exfiltration payloads."),
          context: z.string().optional().describe("Optional retrieved context appended to the prompt."),
        },
      },
      async ({ prompt, context }) => runScan({ prompt, context, toolName: "scan_data_exfiltration" })
    );

    // ── PAID 4: scan_system_leak (0.02 USDT0) ───────────────────────────────
    server.registerTool(
      "scan_system_leak",
      {
        title: "Scan for system-prompt leak/redirection probes",
        description:
          "Detect system-prompt leak/redirection probes (instruction repetition requests, rule extraction, system-prompt reflection, config extraction). Costs 0.02 USDT0.",
        inputSchema: {
          prompt: z.string().describe("The prompt to scan for system-leak probes."),
          context: z.string().optional().describe("Optional retrieved context appended to the prompt."),
        },
      },
      async ({ prompt, context }) => runScan({ prompt, context, toolName: "scan_system_leak" })
    );

    // ── PAID 5: attest_prompt_safety (0.03 USDT0) ───────────────────────────
    server.registerTool(
      "attest_prompt_safety",
      {
        title: "Run full Bulwark pipeline + signed 0G-anchored attestation",
        description:
          "Run the full Bulwark pipeline (all 4 scan categories) and bind the result into an EIP-191 signed attestation report with 0G Merkle root anchoring. Costs 0.03 USDT0.",
        inputSchema: {
          prompt: z.string().describe("The prompt to scan with the full pipeline."),
          context: z.string().optional().describe("Optional retrieved context appended to the prompt."),
        },
      },
      async ({ prompt, context }) => runScan({ prompt, context, toolName: "attest_prompt_safety" })
    );

    // ── FREE 1: bulwark_capabilities ────────────────────────────────────────
    server.registerTool(
      "bulwark_capabilities",
      {
        title: "Bulwark capabilities, rule catalog, policy defaults & pricing",
        description:
          "Return engine limits, detection categories, rule catalog, technique signatures, and tool pricing. Free.",
        inputSchema: {},
      },
      async () => {
        const allTools = [
          ...Array.from(PAID_TOOLS),
          ...FREE_TOOL_NAMES,
        ];
        return textResult({
          service: "EVIDIQ Bulwark MCP",
          version: ENGINE_VERSION,
          policyVersion: POLICY_VERSION,
          policyDefaults: DEFAULT_POLICY_CONFIG,
          detectionCategories: ALL_CATEGORIES,
          severities: ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
          verdicts: ["ALLOW", "WARN", "BLOCK"],
          ruleCatalog: PATTERN_CATALOG.map((r) => ({
            ruleId: r.ruleId,
            category: r.category,
            severity: r.severity,
            action: r.action,
            description: r.description,
            patternCount: r.patterns.length,
          })),
          tools: allTools,
          pricing: {
            paid: TOOL_PRICES_HUMAN,
            free: FREE_TOOL_NAMES,
          },
        });
      }
    );

    // ── FREE 2: validate_prompt_input ───────────────────────────────────────
    server.registerTool(
      "validate_prompt_input",
      {
        title: "Preflight parse-check (no scanning)",
        description:
          "Validate prompt structure, detect encoding anomalies, and check input size limits without scanning for injection. Free.",
        inputSchema: {
          prompt: z.string().optional().describe("Prompt text to validate."),
          context: z.string().optional().describe("Optional context to validate."),
        },
      },
      async ({ prompt, context }) => {
        const p = prompt ?? "";
        const input = context && context.length > 0 ? `${p}\n${context}` : p;
        const cfg = DEFAULT_POLICY_CONFIG;
        const issues: string[] = [];

        if (input.length === 0) {
          issues.push("Input is empty — nothing to scan.");
        }
        if (input.length > cfg.maxInputLength) {
          issues.push(`Input exceeds maxInputLength (${cfg.maxInputLength}); will be truncated for evaluation.`);
        }

        const urlCount = (input.match(/https?:\/\/[^\s<>"'`)]+/g) || []).length;
        const b64Candidates = (input.match(/[A-Za-z0-9+/]{32,}={0,2}/g) || []).filter((s) => s.length % 4 === 0).length;
        const hexCandidates = (input.match(/[0-9a-fA-F]{40,}/g) || []).length;
        const htmlComments = (input.match(/<!--[\s\S]*?-->/g) || []).length;
        const malformedComments = Math.max(0, (input.match(/<!--/g) || []).length - htmlComments);
        let zeroWidthCount = 0;
        for (const cp of ["\u200B", "\u200C", "\u200D", "\u200E", "\u200F", "\u2060", "\u2061", "\u2062", "\u2063", "\u2064", "\uFEFF", "\u00AD"]) {
          zeroWidthCount += input.split(cp).length - 1;
        }

        const valid = issues.length === 0 || (issues.length === 1 && issues[0].startsWith("Input exceeds"));

        return textResult({
          valid,
          inputLength: input.length,
          maxInputLength: cfg.maxInputLength,
          withinSizeLimit: input.length <= cfg.maxInputLength,
          urlCount,
          encodingAnomalies: {
            zeroWidthCount,
            htmlCommentCount: htmlComments,
            malformedCommentCount: malformedComments,
            base64CandidateCount: b64Candidates,
            hexCandidateCount: hexCandidates,
          },
          issues,
          policyVersion: POLICY_VERSION,
          note: "Preflight parse-check only — no injection scanning performed.",
        });
      }
    );

    // ── FREE 3: estimate_cost ───────────────────────────────────────────────
    server.registerTool(
      "estimate_cost",
      {
        title: "Quote exact tool price",
        description: "Return exact atomic and human-readable price for any paid tool. Free.",
        inputSchema: {
          toolName: z.string().optional().describe("Paid tool name to quote."),
        },
      },
      async ({ toolName }) => {
        if (!toolName) {
          return textResult({
            network: "eip155:196",
            asset: "0x779ded0c9e1022225f8e0630b35a9b54be713736",
            symbol: "USDT0",
            pricing: TOOL_PRICES_HUMAN,
            freeTools: FREE_TOOL_NAMES,
          });
        }

        const atomic = TOOL_PRICES_ATOMIC[toolName];
        const human = TOOL_PRICES_HUMAN[toolName];

        if (atomic) {
          return textResult({
            toolName,
            isPaid: true,
            atomicAmount: atomic,
            humanAmount: human,
            chain: "eip155:196",
            asset: "0x779ded0c9e1022225f8e0630b35a9b54be713736",
          });
        }
        if (FREE_TOOL_NAMES.includes(toolName)) {
          return textResult({
            toolName,
            isPaid: false,
            cost: "0 USDT0 (Free preflight tool)",
          });
        }
        return textResult({
          toolName,
          known: false,
          isPaid: false,
          message: `Unknown tool '${toolName}'. Known paid: ${Array.from(PAID_TOOLS).join(", ")}. Known free: ${FREE_TOOL_NAMES.join(", ")}.`,
        });
      }
    );

    // ── FREE 4: verify_bulwark_report ───────────────────────────────────────
    server.registerTool(
      "verify_bulwark_report",
      {
        title: "Offline verification of a Bulwark report",
        description:
          "Offline SHA-256 content digest and EIP-191 signature validator against the 4 mathematical invariants. Free.",
        inputSchema: {
          report: z.any().optional().describe("BulwarkReport object to verify."),
        },
      },
      async ({ report }) => {
        if (!report || typeof report !== "object") {
          return textResult({
            valid: false,
            errors: ["Invalid parameters: `report` object required"],
          });
        }
        const verifyRes = await verifyBulwarkReport(report);
        return textResult({
          valid: verifyRes.valid,
          errors: verifyRes.errors,
          executionId: (report as { metadata?: { executionId?: string } }).metadata?.executionId,
          reportDigest: (report as { receipt?: { reportDigest?: string } }).receipt?.reportDigest,
        });
      }
    );

    // ── FREE 5: get_artifact ────────────────────────────────────────────────
    server.registerTool(
      "get_artifact",
      {
        title: "Retrieve a stored Bulwark artifact",
        description: "Retrieve a stored scan report or 0G Merkle proof by content-addressed ID. Free.",
        inputSchema: {
          artifactId: z.string().optional().describe("Execution ID or report digest hex."),
        },
      },
      async ({ artifactId }) => {
        if (!artifactId) {
          return textResult({
            found: false,
            usage: "Provide `artifactId` to fetch a stored artifact.",
            note: "Free. An artifact id is a content address, not an access-control token.",
          });
        }
        const artifact = ARTIFACT_STORE.get(artifactId);
        if (!artifact) {
          return textResult({
            found: false,
            artifactId,
            message: "Artifact not found in active session store",
          });
        }
        return textResult({ found: true, artifactId, artifact });
      }
    );
  },
  {
    instructions: BULWARK_INSTRUCTIONS,
    capabilities: { tools: {} },
  },
  {
    basePath: "",
    maxDuration: 300,
    verboseLogs: false,
  }
);
