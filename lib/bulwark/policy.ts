/**
 * lib/bulwark/policy.ts
 * Normative policy configuration (PLAN §15). All defaults are normative —
 * changing a default is a policyVersion bump (§17).
 */

export interface BulwarkPolicyConfig {
  maxInputLength: number;          // default: 100000 (chars)
  maxUrlCount: number;             // default: 20 (URLs in a single input)
  patternTruncateLength: number;   // default: 100 (chars shown in matchedPattern)
  scanIndirectInjection: boolean;  // default: true
  zeroWidthDetection: boolean;     // default: true — exactly the 12 codepoints in §6-F.2
  htmlCommentScan: boolean;        // default: true — non-greedy <!--...--> only, per §6-F.3
  base64DecodeScan: boolean;       // default: true — single decode, ≤4096 bytes, per §6-F.1
  maxBase64BlobBytes: number;      // default: 4096
  minBase64CandidateLength: number; // default: 32
  minHexCandidateLength: number;   // default: 40
  minUrlEncodeSequences: number;   // default: 10
  minUnicodeEscapes: number;       // default: 4
}

export const DEFAULT_POLICY_CONFIG: BulwarkPolicyConfig = {
  maxInputLength: 100000,
  maxUrlCount: 20,
  patternTruncateLength: 100,
  scanIndirectInjection: true,
  zeroWidthDetection: true,
  htmlCommentScan: true,
  base64DecodeScan: true,
  maxBase64BlobBytes: 4096,
  minBase64CandidateLength: 32,
  minHexCandidateLength: 40,
  minUrlEncodeSequences: 10,
  minUnicodeEscapes: 4,
};

export const POLICY_VERSION = "bulwark-1.0.0";
export const ENGINE_VERSION = "1.0.0";
