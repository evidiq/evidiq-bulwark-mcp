/**
 * lib/bulwark/detector.ts
 * Deterministic detection engine (PLAN §6, §6-F, §6-G, §16).
 *
 * No model, no network, no random source in the verdict path (§0 defect 12).
 * Same bytes → same trace, violations, verdict.
 */

import crypto from "node:crypto";
import {
  PATTERN_CATALOG,
  BulwarkRuleDef,
  DetectionCategory,
  ENCODING_SMUGGLE_RESCAN_CATEGORIES,
  ZERO_WIDTH_CODEPOINTS,
} from "./patterns.js";
import { BulwarkPolicyConfig, DEFAULT_POLICY_CONFIG } from "./policy.js";
import {
  BulwarkTraceStep,
  BulwarkViolation,
  SeverityLevel,
} from "./report.js";

export interface RawMatch {
  offset: number;
  length: number;
  matchedText: string;
  /** Declaration order; synthetic detections (zero-width) use -1. */
  patternIndex: number;
}

export interface RuleEval {
  rule: BulwarkRuleDef;
  matches: RawMatch[];
  failed: boolean;
  failureMessage?: string;
}

export interface EngineResult {
  scannedInput: string;
  inputHash: string;
  inputLength: number;
  truncated: boolean;
  scanCategories: DetectionCategory[];
  trace: BulwarkTraceStep[];
  violations: BulwarkViolation[];
  evaluationQuality: "FULL" | "DEGRADED";
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** All case-insensitive literal occurrences of `needle` in `input` (UTF-16 offsets). */
function findLiteralMatches(input: string, needle: string, patternIndex: number): RawMatch[] {
  if (!needle) return [];
  const re = new RegExp(escapeRegExp(needle), "gi");
  const out: RawMatch[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(input)) !== null) {
    const text = m[0];
    out.push({ offset: m.index, length: text.length, matchedText: text, patternIndex });
    if (re.lastIndex === m.index) re.lastIndex++; // avoid zero-length loop
  }
  return out;
}

function findAllLiteralMatches(input: string, rule: BulwarkRuleDef): RawMatch[] {
  const all: RawMatch[] = [];
  rule.patterns.forEach((p, idx) => {
    for (const m of findLiteralMatches(input, p.value, idx)) all.push(m);
  });
  return all;
}

/** §6-F.2: scan the frozen 12 zero-width / invisible codepoints. */
function findZeroWidthMatches(input: string): RawMatch[] {
  const out: RawMatch[] = [];
  for (let i = 0; i < input.length; i++) {
    const ch = input[i];
    if (ZERO_WIDTH_CODEPOINTS.includes(ch)) {
      out.push({ offset: i, length: 1, matchedText: ch, patternIndex: -1 });
    }
  }
  return out;
}

function firstMatch(matches: RawMatch[]): RawMatch | null {
  if (matches.length === 0) return null;
  let best = matches[0];
  for (const m of matches) {
    if (m.offset < best.offset || (m.offset === best.offset && m.patternIndex < best.patternIndex)) {
      best = m;
    }
  }
  return best;
}

/** §7-A-Note normative trace strings. */
function buildTraceStep(seq: number, rule: BulwarkRuleDef, eval_: RuleEval): BulwarkTraceStep {
  const fm = eval_.failed ? null : firstMatch(eval_.matches);
  const passed = !eval_.failed && fm === null;
  let actual: string;
  let message: string;
  if (eval_.failed) {
    actual = `${rule.ruleId}:internal_error`;
    message = `${rule.ruleId}:internal_error`;
  } else if (fm) {
    actual = `match@${fm.offset}:${fm.length}`;
    message = `${rule.ruleId}:fail@${fm.offset}`;
  } else {
    actual = "nomatch";
    message = `${rule.ruleId}:pass`;
  }
  return {
    sequence: seq,
    checkId: rule.ruleId,
    category: rule.category,
    severity: rule.severity,
    passed,
    expected: `no ${rule.ruleId} match`,
    actual,
    message,
  };
}

/** §7-B-Note normative violation fields. */
function matchToViolation(rule: BulwarkRuleDef, m: RawMatch, truncate: number): BulwarkViolation {
  return {
    ruleId: rule.ruleId,
    severity: rule.severity,
    action: rule.action,
    message: `${rule.ruleId}:${rule.severity}:${m.offset}`,
    offset: m.offset,
    matchedPattern: m.matchedText.slice(0, truncate),
    category: rule.category,
  };
}

// ── Encoding candidate detection (§6-F.1, §6-F.4) ──────────────────────────

interface EncCandidate {
  kind: "base64" | "hex" | "url" | "unicode";
  offset: number;
  source: string;
  decoded?: string;
  decodeError?: boolean;
  tooLarge?: boolean;
  decodedBytes?: number;
}

function detectEncodingCandidates(input: string, cfg: BulwarkPolicyConfig): EncCandidate[] {
  const out: EncCandidate[] = [];

  // Base64 — standard alphabet, ≥32 chars, ≤4096 decoded bytes (§6-F.1)
  const b64Re = /[A-Za-z0-9+/]{32,}={0,2}/g;
  let m: RegExpExecArray | null;
  while ((m = b64Re.exec(input)) !== null) {
    const src = m[0];
    if (src.length % 4 !== 0) continue;
    let buf: Buffer;
    try {
      buf = Buffer.from(src, "base64");
    } catch {
      continue;
    }
    if (buf.length === 0) continue;
    if (buf.toString("base64") !== src) continue; // strict roundtrip
    const cand: EncCandidate = {
      kind: "base64",
      offset: m.index,
      source: src,
      decodedBytes: buf.length,
    };
    if (buf.length > cfg.maxBase64BlobBytes) {
      cand.tooLarge = true;
    } else {
      cand.decoded = buf.toString("utf-8");
    }
    out.push(cand);
  }

  // Hex — continuous, ≥40 chars (20 bytes), even length (§6-F.4)
  const hexRe = /[0-9a-fA-F]{40,}/g;
  while ((m = hexRe.exec(input)) !== null) {
    const src = m[0];
    if (src.length % 2 !== 0) {
      out.push({ kind: "hex", offset: m.index, source: src, decodeError: true });
      continue;
    }
    const buf = Buffer.from(src, "hex");
    out.push({ kind: "hex", offset: m.index, source: src, decoded: buf.toString("utf-8"), decodedBytes: buf.length });
  }

  // URL encoding — ≥10 consecutive %XX sequences (§6-F.4)
  const urlRe = /(?:%[0-9A-Fa-f]{2}){10,}/g;
  while ((m = urlRe.exec(input)) !== null) {
    const src = m[0];
    try {
      const decoded = decodeURIComponent(src);
      out.push({ kind: "url", offset: m.index, source: src, decoded });
    } catch {
      out.push({ kind: "url", offset: m.index, source: src, decodeError: true });
    }
  }

  // Unicode escape — ≥4 consecutive \uXXXX (§6-F.4)
  const uniRe = /(?:\\u[0-9A-Fa-f]{4}){4,}/g;
  while ((m = uniRe.exec(input)) !== null) {
    const src = m[0];
    let decoded = "";
    const parts = src.match(/\\u[0-9A-Fa-f]{4}/g) || [];
    for (const p of parts) {
      decoded += String.fromCharCode(parseInt(p.slice(2), 16));
    }
    out.push({ kind: "unicode", offset: m.index, source: src, decoded });
  }

  return out;
}

/** Scan decoded content with direct+jailbreak+system_leak literal patterns only (§6-F.4). */
function decodedTriggersBlock(input: string): { ruleId: string; offset: number } | null {
  for (const rule of PATTERN_CATALOG) {
    if (!ENCODING_SMUGGLE_RESCAN_CATEGORIES.includes(rule.category)) continue;
    if (rule.action !== "BLOCK") continue;
    for (let i = 0; i < rule.patterns.length; i++) {
      const re = new RegExp(escapeRegExp(rule.patterns[i].value), "i");
      const mm = re.exec(input);
      if (mm) {
        return { ruleId: rule.ruleId, offset: mm.index };
      }
    }
  }
  return null;
}

// ── HTML comment malformed counting (§6-F.3) ───────────────────────────────

function countMalformedComments(input: string): number {
  const total = (input.match(/<!--/g) || []).length;
  const complete = (input.match(/<!--[\s\S]*?-->/g) || []).length;
  return Math.max(0, total - complete);
}

// ── §8-A violation dedup + sort ─────────────────────────────────────────────

function dedupAndSortViolations(violations: BulwarkViolation[]): BulwarkViolation[] {
  const seen = new Set<string>();
  const unique: BulwarkViolation[] = [];
  for (const v of violations) {
    const key = `${v.ruleId}\u0000${v.offset ?? "none"}\u0000${v.matchedPattern ?? ""}`;
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(v);
  }
  unique.sort((a, b) => {
    const oa = a.offset ?? -1;
    const ob = b.offset ?? -1;
    if (oa !== ob) return oa - ob;
    if (a.ruleId !== b.ruleId) return a.ruleId < b.ruleId ? -1 : 1;
    const ma = a.matchedPattern ?? "";
    const mb = b.matchedPattern ?? "";
    if (ma !== mb) return ma < mb ? -1 : 1;
    return 0;
  });
  return unique;
}

// ── Main pipeline ───────────────────────────────────────────────────────────

export function runBulwarkEvaluation(params: {
  input: string;
  categories: readonly DetectionCategory[];
  policy?: Partial<BulwarkPolicyConfig>;
}): EngineResult {
  const cfg: BulwarkPolicyConfig = { ...DEFAULT_POLICY_CONFIG, ...params.policy };
  const scope = params.categories;

  let truncated = false;
  let scannedInput = params.input;
  if (scannedInput.length > cfg.maxInputLength) {
    scannedInput = scannedInput.slice(0, cfg.maxInputLength);
    truncated = true;
  }

  let degraded = truncated;

  const rulesInScope = PATTERN_CATALOG.filter((r) => scope.includes(r.category));

  const evals: RuleEval[] = [];
  for (const rule of rulesInScope) {
    try {
      let matches: RawMatch[] = [];
      if (rule.ruleId === "indirect.hidden_instruction" && cfg.zeroWidthDetection && cfg.scanIndirectInjection) {
        matches = matches.concat(findZeroWidthMatches(scannedInput));
      }
      matches = matches.concat(findAllLiteralMatches(scannedInput, rule));
      evals.push({ rule, matches, failed: false });
    } catch (err: unknown) {
      // §6-G trigger 5 — fail closed.
      degraded = true;
      evals.push({ rule, matches: [], failed: true, failureMessage: (err as Error).message || String(err) });
    }
  }

  // Extra detection: encoding candidates (indirect.encoding_smuggle + exfil.encoded_extract)
  const encodingActive = scope.includes("indirect_injection") || scope.includes("exfiltration");
  const candidates = encodingActive ? detectEncodingCandidates(scannedInput, cfg) : [];

  // HTML comment malformed count → degraded (§6-G trigger 2)
  if (cfg.htmlCommentScan && countMalformedComments(scannedInput) > 5) {
    degraded = true;
  }

  // Build violations from rule evals
  const violations: BulwarkViolation[] = [];
  for (const ev of evals) {
    if (ev.failed) {
      // Defensive fail-closed violation with absent offset (§7-B-Note "none").
      violations.push({
        ruleId: ev.rule.ruleId,
        severity: ev.rule.severity,
        action: ev.rule.action,
        message: `${ev.rule.ruleId}:${ev.rule.severity}:none`,
        category: ev.rule.category,
      });
      continue;
    }
    for (const m of ev.matches) {
      violations.push(matchToViolation(ev.rule, m, cfg.patternTruncateLength));
    }
  }

  // encoding_smuggle violations (indirect in scope): decoded content triggers BLOCK rule
  if (scope.includes("indirect_injection")) {
    for (const c of candidates) {
      if (c.decodeError) {
        degraded = true; // §6-G trigger 3
        continue;
      }
      if (c.tooLarge) {
        degraded = true; // §6-G trigger 1
        continue;
      }
      if (c.decoded && decodedTriggersBlock(c.decoded)) {
        violations.push({
          ruleId: "indirect.encoding_smuggle",
          severity: "MEDIUM",
          action: "WARN",
          message: `indirect.encoding_smuggle:MEDIUM:${c.offset}`,
          offset: c.offset,
          matchedPattern: c.source.slice(0, cfg.patternTruncateLength),
          category: "indirect_injection",
        });
      }
    }
  }

  // exfil.encoded_extract violations (exfiltration in scope): large base64 blobs + large hex
  if (scope.includes("exfiltration")) {
    for (const c of candidates) {
      if (c.kind === "base64" && c.tooLarge) {
        violations.push({
          ruleId: "exfil.encoded_extract",
          severity: "MEDIUM",
          action: "WARN",
          message: `exfil.encoded_extract:MEDIUM:${c.offset}`,
          offset: c.offset,
          matchedPattern: c.source.slice(0, cfg.patternTruncateLength),
          category: "exfiltration",
        });
      } else if (c.kind === "hex" && !c.decodeError && (c.decodedBytes ?? 0) >= cfg.minHexCandidateLength * 4 / 2) {
        violations.push({
          ruleId: "exfil.encoded_extract",
          severity: "MEDIUM",
          action: "WARN",
          message: `exfil.encoded_extract:MEDIUM:${c.offset}`,
          offset: c.offset,
          matchedPattern: c.source.slice(0, cfg.patternTruncateLength),
          category: "exfiltration",
        });
      }
    }
  }

  // Trace steps (sequence follows pipeline = catalogue order in scope)
  const trace: BulwarkTraceStep[] = evals.map((ev, idx) => buildTraceStep(idx + 1, ev.rule, ev));

  const finalViolations = dedupAndSortViolations(violations);

  const inputHash = "0x" + crypto.createHash("sha256").update(scannedInput, "utf-8").digest("hex");

  return {
    scannedInput,
    inputHash,
    inputLength: scannedInput.length,
    truncated,
    scanCategories: scope.slice(),
    trace,
    violations: finalViolations,
    evaluationQuality: degraded ? "DEGRADED" : "FULL",
  };
}
