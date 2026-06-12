# ADR-0001 — Single package, BCL-only, strict JOSE profile

Date: 2026-06-12
Status: LOCKED

## Context

In the official Microsoft ecosystem, JWE only exists inside the
`Microsoft.IdentityModel.*` stack: heavy, fragmented across interdependent
packages, coupled to its own token-validation model — and unable to *issue*
AES-GCM JWE (`IDX10715`). We decided to build an independent, publishable
implementation.

## D1 — One package, family by namespaces (LOCKED)

`Matios.Security` is ONE csproj → ONE NuGet package. `Jose` and `Jwt` are
internal namespaces, NOT separate packages.

**Why**: JWT is built ON TOP of JOSE — splitting them is an artificial
boundary (the anti-example is the `Microsoft.IdentityModel.*` fragmentation
and its version-alignment pain; the healthy example is `jose-jwt` /
`System.IdentityModel.Tokens.Jwt`: one package with everything). Total
weight: tens of KB — nobody wins from the split.

**Graduation rule** for a future sibling package `Matios.Security.X`:
(a) it brings its own external dependency, or (b) it has a distinct
audience/lifecycle. If neither holds, it lives as a namespace.

## D2 — BCL-only isolation (LOCKED, non-negotiable)

Allowed dependencies: ONLY the BCL (`System.Security.Cryptography`,
`System.Text.Json`). Zero external NuGets, zero application-platform types.
The dependency arrow points INTO this package (consumers reference it),
never out of it. This is what keeps the package publishable.

## D3 — MVP scope: `dir` + `A256GCM` + Nested JWT (LOCKED)

- JWE Compact Serialization (RFC 7516 §3.1, §5.1, §5.2).
- Key management: **`dir`** (Direct Encryption) — the primary use case is
  issuer == validator, so no asymmetric envelope is needed.
- Content encryption: **`A256GCM`**.
- JWS **`HS256`** — minimum required for Nested JWT (`cty: "JWT"`).
- Phase 2 (only when a real interop case demands it): `A256KW`,
  `RSA-OAEP-256`, `ECDH-ES(+A256KW)`, `A128CBC-HS256`, `RS256`.

## D4 — Protocol security rules (LOCKED)

1. **`zip` rejected by design** — issue and parse (compression-oracle class,
   CRIME/BREACH). A token carrying `zip` throws.
2. **Unknown `crit` ⇒ reject** (RFC 7515 §4.1.11 / 7516 §4.1.13). The MVP
   supports no critical parameters, so any `crit` rejects.
3. **Anti algorithm-confusion**: the caller declares the accepted `alg`/`enc`
   whitelists when decrypting/verifying; the header NEVER decides alone.
   `alg: none` does not exist in the API.
4. **Fresh randomness per token**: 96-bit IV from a CSPRNG on every encrypt.
5. **AAD = `ASCII(BASE64URL(protected header))`** exactly (RFC 7516 §5.1 step 14).
6. **Anti-oracle errors**: a single `JoseException` with a fixed generic
   message; the fine-grained `FailureCode` is for server-side logging only.
7. **Strict uniqueness**: duplicate header parameter names (RFC 7515 §4) and
   duplicate claim names (RFC 7519 §4) are rejected.
8. Defensive token-size limits on every parse.

## D5 — Target `net10.0`

`AesGcm` and modern BCL APIs available natively. Multi-targeting
(`netstandard2.0`) only if a real consumer demands it.

## D6 — Quality gate (LOCKED)

Definition of done for every release:

1. Official RFC 7515 A.1 vector green. (Note: RFC 7520 carries no official
   vector for `dir`+`A256GCM` — its §5.6 uses A128GCM — so JWE conformance is
   verified by point 2, which is stronger.)
2. Interop against `Microsoft.IdentityModel.JsonWebTokens` (an independent
   implementation): tokens issued here validate there, and vice versa for
   JWS. A canary test pins Microsoft's `IDX10715` issue-side limitation.
3. Full strict negative suite (every D4 rule has its test).
4. Build 0/0 with `TreatWarningsAsErrors`, package produced.

## Consequences

- Independent SemVer per package (NuGet requires it).
- Maintaining a protocol-level crypto library: mitigated by D4 + D6 — no
  primitives are invented; the RFCs are composed over the BCL with official
  vectors and an independent implementation as the safety net.
