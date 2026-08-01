# EVIDIQ Bulwark MCP — Prompt Injection & LLM Input Safety Guard Service

Deterministic prompt-injection, jailbreak, data-exfiltration, and system-prompt-leak scanner for autonomous AI agents. Pattern lexicons, structural heuristics, and known-technique signatures — no model in the verdict path, so the same bytes always give the same answer. Full scan report digests (JCS canonical SHA-256) are anchored to 0G Storage as Merkle roots.

---

## Service Overview

- **Service Name**: `EVIDIQ-Bulwark`
- **Network**: `eip155:196` (X Layer Mainnet)
- **Payment Asset**: `USD₮0` (`0x779ded0c9e1022225f8e0630b35a9b54be713736`)
- **Protocol**: x402 v2 payment gate on HTTP POST `/mcp` (Phase 2; Phase 1 bypass)
- **Public Endpoint**: `https://mcp.evidiq.dev/bulwark`
- **Policy Version**: `bulwark-1.0.0` (frozen pattern catalogue)

---

## 10 Tools Specification

### Paid Scan Tools (x402 Gated — Phase 2; Phase 1 bypass/free)

1. **`scan_prompt_injection`** — `0.005 USD₮0` (5,000 atomic)
   - Scans for direct prompt injection (role hijack, instruction override, delimiter violation) and indirect injection (hidden instructions, tool hijack, encoding smuggle in retrieved/RAG content).
2. **`scan_jailbreak_techniques`** — `0.01 USD₮0` (10,000 atomic)
   - Detects known jailbreak technique signatures (DAN variants, prefix injection, roleplay bypass, credential interleaving).
3. **`scan_data_exfiltration`** — `0.015 USD₮0` (15,000 atomic)
   - Detects data exfiltration payloads (URL-based extraction, encoded large blobs, tool-call hijack for data theft).
4. **`scan_system_leak`** — `0.02 USD₮0` (20,000 atomic)
   - Detects system-prompt leak/redirection probes (instruction repetition, rule extraction, system-prompt reflection, config extraction).
5. **`attest_prompt_safety`** — `0.03 USD₮0` (30,000 atomic)
   - Runs the full Bulwark pipeline (all 4 scan categories) and binds the result into an EIP-191 signed attestation report with 0G Merkle root anchoring.

### Free Discovery & Preflight Tools

6. **`bulwark_capabilities`** — `FREE`
   - Returns engine limits, detection categories, rule catalog, technique signatures, policy defaults, and tool pricing.
7. **`validate_prompt_input`** — `FREE`
   - Preflight parse-check: validates prompt structure, detects encoding anomalies, and checks input size limits without scanning for injection.
8. **`estimate_cost`** — `FREE`
   - Returns exact atomic and human-readable price for any paid tool.
9. **`verify_bulwark_report`** — `FREE`
   - Offline SHA-256 content digest and EIP-191 signature validator against the 4 mathematical invariants.
10. **`get_artifact`** — `FREE`
    - Retrieves a stored scan report or 0G Merkle proof by content-addressed ID.

---

## Verdict Precedence

- **`BLOCK`** — ≥1 detection with severity `CRITICAL` or `HIGH`. Prompt MUST NOT be forwarded to the LLM.
- **`WARN`** — ≥1 detection with severity `MEDIUM` or `LOW`. Prompt may proceed with caution.
- **`ALLOW`** — no detections.

A report with zero violations and zero failed trace steps always returns `ALLOW`.

---

## x402 Payment Instructions for AI Agents

When invoking any paid tool, if payment is required, the server returns HTTP `402 Payment Required` with:

- `payment-required: <base64-encoded x402 v2 challenge>`
- `x-payment-required: <base64-encoded x402 v2 challenge>`
- JSON body with `x402Version: 2`, `accepts[0]` carrying `scheme`/`network`/`asset`/`amount`/`payTo`.

Sign the EIP-712 challenge, then retry the same request with a `PAYMENT-SIGNATURE` header. On settlement the server returns `200` with the tool result and a `PAYMENT-RESPONSE: {"status":"settled","transaction":"<tx>"}` header.

> Phase 1 test build: `BULWARK_X402_BYPASS=1` — all tools return 200, no payment required.

---

## Use it from any agent

```bash
# Read the public Skill document
curl -s https://mcp.evidiq.dev/bulwark/skill.md

# Inspect x402 pricing discovery
curl -s https://mcp.evidiq.dev/bulwark/x402

# Connect remote MCP server (OpenClaw)
openclaw mcp add evidiq-bulwark --transport streamable-http --url https://mcp.evidiq.dev/bulwark/mcp

# Connect remote MCP server (Claude Code)
claude mcp add --transport http evidiq-bulwark https://mcp.evidiq.dev/bulwark/mcp
```

---

## Determinism & Privacy

The verdict path contains no model, no network fetch, and no random source. The `reportDigest` is `SHA-256(JCS(report))` (RFC 8785 canonical JSON) and is reproducible for identical input + signing key. Processing pipelines include zero-width/invisible character detection (12 frozen codepoints), HTML-comment scanning, and single-level base64/hex/URL/unicode-escape decoding. The report never stores the raw prompt — only `inputHash` (SHA-256), offsets, and truncated matched patterns (≤100 chars).
