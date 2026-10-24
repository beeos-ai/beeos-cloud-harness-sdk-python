# Changelog

All notable changes to `beeos-cloud-harness-sdk` are documented here. This project
follows Semantic Versioning.

## [1.0.1] - 2026-10-25

Staging release (PATCH from the published 1.0.0). Additive: existing exports keep
their signatures.

- Add the runtime original-intent, memory and chat-store contracts for native
  runtimes (`runtime_original_intent`, `runtime_memory`, `runtime_chat_store`,
  `chat_store_contract`), exported from the package root.
- Add `grant_jwks` (grant JWKS verification) and `jcs` (JSON canonicalization).
- `Gateway.token(sandbox_id=None)`: a Sandbox v1 guest may name its claimed
  `sandbox_id`; the request body is unchanged without it.
- Add `uv.lock`.
