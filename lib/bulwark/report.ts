/**
 * lib/bulwark/report.ts
 * Canonical report, digest & signature (PLAN §7, §8, §9, §17).
 *
 * Determinism contract (§17): for identical input + signing key, `verdict`,
 * `trace`, `violations`, `checksEvaluated`, `reportDigest`, `policyVersion`
 * and `signature` MUST be byte-identical across conforming implementations.
 * `executionId`, `evaluationTimeMs`, `timestamp` are explicitly non-deterministic.
 *
 * Therefore `reportDigest` is computed over the deterministic subset only:
 *   SHA-256(JCS({ metadata \ {executionId,evaluationTimeMs,timestamp},
 *                verdict, trace, violations,
 *                receipt \ {reportDigest,signature,zeroGAnchorTx,zeroGStorageRoot} }))
 * 0G anchoring is post-report (§16 step 10) and does not affect the digest.
 */

import crypto from "node:crypto";
import { privateKeyToAccount } from "viem/accounts";
import { hashMessage, recoverAddress } from "viem";
import { POLICY_VERSION, ENGINE_VERSION } from "./policy.js";

export type SeverityLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
export type EvaluationVerdict = "ALLOW" | "WARN" | "BLOCK";

export type DetectionCategory =
  | "direct_injection"
  | "indirect_injection"
  | "jailbreak"
  | "exfiltration"
  | "system_leak";

export interface BulwarkTraceStep {
  sequence: number;
  checkId: string;
  category: DetectionCategory;
  severity: SeverityLevel;
  passed: boolean;
  expected: string;
  actual: string;
  message: string;
}

export interface BulwarkViolation {
  ruleId: string;
  severity: SeverityLevel;
  action: "BLOCK" | "WARN";
  message: string;
  offset?: number;
  matchedPattern?: string;
  category: string;
}

export interface BulwarkMetadata {
  executionId: string;
  inputHash: string;
  inputLength: number;
  scanCategories: string[];
  checksEvaluated: number;
  policyVersion: string;
  evaluationTimeMs: number;
  evaluationQuality: "FULL" | "DEGRADED";
  engineVersion: string;
  timestamp: string;
}

export interface BulwarkReceipt {
  reportDigest: string;
  verdict: EvaluationVerdict;
  signerAddress: string;
  signature: string;
  zeroGAnchorTx?: string;
  zeroGStorageRoot?: string;
}

export interface BulwarkReport {
  metadata: BulwarkMetadata;
  verdict: EvaluationVerdict;
  trace: BulwarkTraceStep[];
  violations: BulwarkViolation[];
  receipt: BulwarkReceipt;
}

/** RFC 8785 Canonical JSON (JCS): keys sorted lexicographically by UTF-8 code point. */
export function canonicalJsonStringify(obj: unknown): string {
  if (obj === null || obj === undefined || typeof obj !== "object") {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return "[" + obj.map(canonicalJsonStringify).join(",") + "]";
  }
  const parts: string[] = [];
  for (const key of Object.keys(obj as Record<string, unknown>).sort()) {
    const val = (obj as Record<string, unknown>)[key];
    if (val === undefined) continue;
    parts.push(`${JSON.stringify(key)}:${canonicalJsonStringify(val)}`);
  }
  return "{" + parts.join(",") + "}";
}

function sha256Hex(text: string): string {
  return crypto.createHash("sha256").update(text, "utf-8").digest("hex");
}

/**
 * reportDigest = SHA-256(JCS(deterministic subset of report)).
 * Excludes reportDigest, signature, zeroG* (post-report), and the three
 * non-deterministic metadata fields (§17).
 */
export function computeReportDigest(report: {
  metadata: BulwarkMetadata;
  verdict: EvaluationVerdict;
  trace: BulwarkTraceStep[];
  violations: BulwarkViolation[];
  receipt: Pick<BulwarkReceipt, "verdict" | "signerAddress">;
}): string {
  const deterministic = {
    metadata: {
      inputHash: report.metadata.inputHash,
      inputLength: report.metadata.inputLength,
      scanCategories: report.metadata.scanCategories,
      checksEvaluated: report.metadata.checksEvaluated,
      policyVersion: report.metadata.policyVersion,
      evaluationQuality: report.metadata.evaluationQuality,
      engineVersion: report.metadata.engineVersion,
    },
    verdict: report.verdict,
    trace: report.trace,
    violations: report.violations,
    receipt: {
      verdict: report.receipt.verdict,
      signerAddress: report.receipt.signerAddress,
    },
  };
  return "0x" + sha256Hex(canonicalJsonStringify(deterministic));
}

/** Resolve signer key from env (no fallback string — §0 defect 1). */
function getSignerKey(): `0x${string}` | null {
  const raw = process.env.BULWARK_SIGNER_PRIVATE_KEY?.trim();
  if (!raw) return null;
  const hex = raw.startsWith("0x") ? raw : `0x${raw}`;
  if (/^0x[0-9a-fA-F]{64}$/.test(hex)) return hex as `0x${string}`;
  return null;
}

export function bulwarkSignerAvailable(): boolean {
  return getSignerKey() !== null;
}

function requireSigner(): { privateKey: `0x${string}`; address: `0x${string}` } {
  const pk = getSignerKey();
  if (!pk) {
    console.error("[bulwark] FATAL: BULWARK_SIGNER_PRIVATE_KEY missing or invalid. Refusing to sign (§0 defect 1).");
    process.exit(1);
  }
  const account = privateKeyToAccount(pk);
  return { privateKey: pk, address: account.address };
}

export interface CreateReportInput {
  input: string;
  inputHash: string;
  scanCategories: readonly DetectionCategory[];
  trace: BulwarkTraceStep[];
  violations: BulwarkViolation[];
  evaluationQuality: "FULL" | "DEGRADED";
  evaluationStartTimeMs: number;
  zeroGAnchorTx?: string;
  zeroGStorageRoot?: string;
  /** Test-fixture signer key only (allowed outside test fixtures: never). */
  signerPrivateKey?: `0x${string}`;
}

export async function createBulwarkReport(params: CreateReportInput): Promise<BulwarkReport> {
  const timestamp = new Date().toISOString();
  const evaluationTimeMs = Date.now() - params.evaluationStartTimeMs;

  const scanCategories = [...params.scanCategories].sort();

  const orderedTrace: BulwarkTraceStep[] = params.trace.map((step, idx) => ({
    ...step,
    sequence: idx + 1,
  }));

  const signer = params.signerPrivateKey
    ? {
        privateKey: params.signerPrivateKey,
        address: privateKeyToAccount(params.signerPrivateKey).address,
      }
    : requireSigner();

  const executionId = `bulwark_exec_${Date.now()}_${sha256Hex(params.inputHash + timestamp).slice(0, 8)}`;

  const metadata: BulwarkMetadata = {
    executionId,
    inputHash: params.inputHash,
    inputLength: params.input.length,
    scanCategories,
    checksEvaluated: orderedTrace.length,
    policyVersion: POLICY_VERSION,
    evaluationTimeMs,
    evaluationQuality: params.evaluationQuality,
    engineVersion: ENGINE_VERSION,
    timestamp,
  };

  const digest = computeReportDigest({
    metadata,
    verdict: deriveVerdict(params.violations),
    trace: orderedTrace,
    violations: params.violations,
    receipt: { verdict: deriveVerdict(params.violations), signerAddress: signer.address },
  });

  const account = privateKeyToAccount(signer.privateKey);
  const signature = await account.signMessage({
    message: { raw: digest as `0x${string}` },
  });

  const verdict = deriveVerdict(params.violations);

  const receipt: BulwarkReceipt = {
    reportDigest: digest,
    verdict,
    signerAddress: signer.address,
    signature,
    ...(params.zeroGAnchorTx ? { zeroGAnchorTx: params.zeroGAnchorTx } : {}),
    ...(params.zeroGStorageRoot ? { zeroGStorageRoot: params.zeroGStorageRoot } : {}),
  };

  return {
    metadata,
    verdict,
    trace: orderedTrace,
    violations: params.violations,
    receipt,
  };
}

/** §5-B precedence: BLOCK > WARN > ALLOW. */
export function deriveVerdict(violations: BulwarkViolation[]): EvaluationVerdict {
  if (violations.some((v) => v.action === "BLOCK")) return "BLOCK";
  if (violations.some((v) => v.action === "WARN")) return "WARN";
  return "ALLOW";
}

/**
 * Offline verification against the 4 mathematical invariants (§9).
 * Returns a normal result with `valid`/`errors` — never throws, never isError.
 */
export async function verifyBulwarkReport(report: unknown): Promise<{ valid: boolean; errors: string[] }> {
  const errors: string[] = [];

  if (!report || typeof report !== "object") {
    return { valid: false, errors: ["Invalid parameters: report object required"] };
  }
  const r = report as Partial<BulwarkReport> & {
    metadata?: Partial<BulwarkMetadata>;
    receipt?: Partial<BulwarkReceipt>;
    trace?: BulwarkTraceStep[];
    violations?: BulwarkViolation[];
    verdict?: EvaluationVerdict;
  };

  if (!r.metadata || !r.trace || !r.violations || !r.receipt || !r.verdict) {
    return { valid: false, errors: ["Report missing required top-level fields"] };
  }

  // Invariant 1: Trace Consistency
  if (r.metadata.checksEvaluated !== r.trace.length) {
    errors.push(
      `Invariant #1 failed: metadata.checksEvaluated (${r.metadata.checksEvaluated}) != trace.length (${r.trace.length})`
    );
  }

  // Invariant 2: Violation Count (>= per §9.2)
  const failedTraceCount = r.trace.filter((t) => !t.passed).length;
  if (r.violations.length < failedTraceCount) {
    errors.push(
      `Invariant #2 failed: violations.length (${r.violations.length}) < failed trace count (${failedTraceCount})`
    );
  }

  // Invariant 3: Verdict Determinism
  const hasBlock = r.violations.some((v) => v.action === "BLOCK");
  if ((r.verdict === "BLOCK") !== hasBlock) {
    errors.push(
      `Invariant #3 failed: verdict (${r.verdict}) does not match violation actions (hasBlock: ${hasBlock})`
    );
  }

  // Invariant 4: Integrity Digest & EIP-191 Signature
  const expectedDigest = computeReportDigest({
    metadata: r.metadata as BulwarkMetadata,
    verdict: r.verdict,
    trace: r.trace,
    violations: r.violations,
    receipt: {
      verdict: r.receipt.verdict as EvaluationVerdict,
      signerAddress: r.receipt.signerAddress as string,
    },
  });
  if (r.receipt.reportDigest !== expectedDigest) {
    errors.push(
      `Invariant #4 failed: receipt.reportDigest (${r.receipt.reportDigest}) != computed digest (${expectedDigest})`
    );
  }

  try {
    const recovered = await recoverAddress({
      hash: hashMessage({ raw: r.receipt.reportDigest as `0x${string}` }),
      signature: r.receipt.signature as `0x${string}`,
    });
    if (recovered.toLowerCase() !== (r.receipt.signerAddress as string).toLowerCase()) {
      errors.push(
        `Signature mismatch: recovered ${recovered} != claimed signer ${r.receipt.signerAddress}`
      );
    }
  } catch (err: unknown) {
    errors.push(`Signature verification failed: ${(err as Error).message || String(err)}`);
  }

  return { valid: errors.length === 0, errors };
}

/** SHA-256 hex (0x-prefixed) of the scanned input — never store the raw input. */
export function hashInput(input: string): string {
  return "0x" + sha256Hex(input);
}
