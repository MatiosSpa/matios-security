<p align="center">
  <img src="./assets/icon.png" alt="Matios.Security" width="160"/>
</p>

<h1 align="center">Matios.Security</h1>

<p align="center">
  Dependency-free JOSE + JWT for .NET — built only on the BCL.<br>
  JWE (RFC 7516) &nbsp;·&nbsp; JWS (RFC 7515) &nbsp;·&nbsp; JWT (RFC 7519) &nbsp;·&nbsp; Nested JWT
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT">
  <img src="https://img.shields.io/badge/dependencies-0-brightgreen.svg" alt="Zero dependencies">
  <img src="https://img.shields.io/badge/.NET-10.0-512BD4.svg" alt=".NET 10">
  <img src="https://github.com/MatiosSpa/matios-security/actions/workflows/ci.yml/badge.svg" alt="CI">
  &nbsp;·&nbsp; <a href="./README.es.md">Español</a>
</p>

---

## What is JOSE?

**JOSE** — *JSON Object Signing and Encryption* — is the IETF standards family behind modern web tokens:

| RFC | Piece | What it does |
|---|---|---|
| [7515](https://www.rfc-editor.org/rfc/rfc7515) | **JWS** | Signed content — integrity + authenticity |
| [7516](https://www.rfc-editor.org/rfc/rfc7516) | **JWE** | Encrypted content — confidentiality |
| [7517](https://www.rfc-editor.org/rfc/rfc7517) | **JWK** | Keys represented as JSON |
| [7518](https://www.rfc-editor.org/rfc/rfc7518) | **JWA** | The algorithm catalog the others reference |
| [7519](https://www.rfc-editor.org/rfc/rfc7519) | **JWT** | Claims (tokens) built on top of JWS/JWE |

---

## Why Matios.Security

Most JWT stacks for .NET are heavy, fragmented across interdependent packages, or unable to actually *encrypt* tokens with modern AEAD.

Matios.Security takes a different approach:

| | |
|---|---|
| **Zero dependencies** | Built only on `System.Security.Cryptography` and `System.Text.Json` — nothing else, ever |
| **Encrypts what Microsoft's stack cannot** | `Microsoft.IdentityModel.*` can *decrypt* JWE `A256GCM` but cannot *issue* it (`IDX10715`). This library issues and consumes `dir`+`A256GCM` — and interops with Microsoft for validation |
| **Strict by design** | Closed algorithm enums (no magic strings, no `alg:"none"`), caller-side whitelists — the token header never decides on its own |
| **Anti-oracle errors** | One generic exception; the fine-grained failure code is for server-side logging only |
| **Easy to audit** | A handful of small, readable files — a strict, testable profile of the JOSE RFCs |

---

## Quick Start

```
dotnet add package Matios.Security
```

### Minimal Usage

```csharp
using Matios.Security.Jose;
using Matios.Security.Jwt;

// Use DIFFERENT keys for signing and encryption. Minimum 256 bits.
SymmetricJoseKey signingKey = SymmetricJoseKey.FromBase64Url(signingKeyB64, "sig-2026");
SymmetricJoseKey encryptionKey = SymmetricJoseKey.FromBase64Url(encryptionKeyB64, "enc-2026");

// Signed JWT (JWS) — add ONE line to make it encrypted (Nested JWT)
string token = new JwtBuilder()
    .Issuer("my-platform")
    .Audience("my-api")
    .Subject(userId)
    .IdAuto()
    .Lifetime(TimeSpan.FromMinutes(30))
    .Claim("RoleId", 7)                          // private claims: any JSON-serializable value
    .Claim("companyIds", new List<long> { 1, 4, 9 })
    .SignWith(signingKey)
    .EncryptWith(encryptionKey)                  // ← JWE dir+A256GCM outside, signature inside
    .Create();

// Validation
JwtClaims claims = JwtValidator.Validate(token, new JwtValidationParameters
{
    SigningKey = signingKey,
    DecryptionKey = encryptionKey,   // set ⇒ token MUST be JWE (no silent downgrade)
    ValidIssuer = "my-platform",
    ValidAudience = "my-api"
});

long roleId = claims.GetClaim<long>("RoleId");
```

---

## Building locally

No special tooling — just the .NET 10 SDK:

```bash
dotnet build src/Matios.Security/Matios.Security.csproj
dotnet test tests/Matios.Security.Tests/Matios.Security.Tests.csproj
dotnet pack src/Matios.Security/Matios.Security.csproj -o artifacts
```

---

## Security model

Matios.Security implements a **strict profile** of the JOSE RFCs:

- **Caller-side whitelists** — when decrypting/verifying, *you* declare the accepted `alg`/`enc`; the token header never decides alone (anti algorithm-confusion).
- **`alg: "none"` does not exist** in the API. It never will.
- **`zip` rejected** on issue and parse (compression-oracle class, CRIME/BREACH).
- **Unknown `crit` rejected** (RFC 7515 §4.1.11).
- **Duplicate header/claim names rejected** (RFC 7515 §4 / RFC 7519 §4, strict option).
- **Encrypt-without-sign forbidden** — a `dir` JWE without an inner signature does not authenticate the issuer.
- **Constant-time HMAC comparison**, fresh 96-bit IV per token from a CSPRNG, key material wiped on dispose.

---

## API surface

### `Matios.Security.Jose`
`Jwe` (Encrypt / Decrypt) · `Jws` (Sign / Verify) · `SymmetricJoseKey` · `JoseHeader` · `JoseException` + `JoseFailureCode` · options/results records

### `Matios.Security.Jwt`
`JwtBuilder` (fluent issue, dynamic claims, Nested JWT) · `JwtValidator` (Validate / TryValidate) · `JwtClaims` (typed claim reads) · `JwtValidationParameters`

---

## Error model

Every failure throws the single `JoseException` with a fixed, generic message (anti-oracle). The detail lives in `JoseException.FailureCode` (`TokenExpired`, `SignatureInvalid`, `AlgorithmNotAccepted`, …) and is meant for **server-side logging only** — always answer clients generically.

```csharp
if (!JwtValidator.TryValidate(token, parameters, out var claims, out var failure))
{
    _logger.LogWarning("Token rejected: {Code}", failure);  // detail goes to the log
    return Unauthorized();                                   // generic answer to the client
}
```

---

## Scope — deliberately minimal

| Supported (v0.x) | Not supported, by design |
|---|---|
| JWE Compact `dir` + `A256GCM` | `zip` (compression oracle) — rejected, ever |
| JWS Compact `HS256` | `alg: "none"` — does not exist in the API |
| Nested JWT (`cty:"JWT"`) | JSON Serialization / multi-recipient |
| JWK `kty:"oct"` key input | `RSA-OAEP` / `ECDH-ES` / `A256KW` / `A128CBC-HS256` / `RS256` (future, if real interop demands them) |

Everything implemented is conformant and covered by tests; everything outside the profile is **cleanly rejected** — the conformant behavior for an implementation that does not support a feature.

---

## Repository structure

```
matios-security/
├── README.md · README.es.md · LICENSE
├── assets/                  # package icon
├── src/Matios.Security/
│   ├── Jose/                # JWE · JWS · keys · headers · errors
│   └── Jwt/                 # builder · validator · claims
├── tests/Matios.Security.Tests/
└── docs/
    ├── usage.md             # full usage guide
    ├── adr/                 # architecture decision records
    └── diagrams/            # C4 context + containers (PlantUML)
```

---

## Conformance evidence

- **RFC 7515 Appendix A.1** official HS256 vector (accept + tampered-reject).
- **Interop**: tokens issued by this library are decrypted and validated by `Microsoft.IdentityModel.JsonWebTokens` (an independent implementation), and vice versa for JWS. Canary tests pin Microsoft's two limitations: it cannot *issue* `A256GCM` anywhere (`IDX10715`), and it cannot *decrypt* it on Linux/macOS — while this library does both, on every platform.
- **Strict negative suite**: `zip`, `crit`, algorithm confusion, `none`, non-empty Encrypted Key with `dir`, tampered AAD/tag, duplicate header/claim names, BOM'd headers, oversized tokens, undersized keys.
- **49 tests, all green, on every CI run.**

---

## Design Principles

- BCL-only, forever — the dependency arrow points *into* this package, never out of it
- One package; the family lives in namespaces, not in package ids
- Strict profile over broad surface — what is not supported is cleanly rejected
- The caller decides the accepted algorithms, never the token
- Errors are generic outward, precise inward
- Source is small, readable and audit-friendly

See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for the full coding conventions, rules, and development flow.

---

## Status

Matios.Security is **v0.x** — the implemented profile is stable, tested and interop-verified; the public API may still evolve before `1.0.0`.

---

## Documentation

- [`docs/usage.md`](./docs/usage.md) — full usage guide (keys, claims strategy, validation posture, error handling, ASP.NET Core integration).
- [`docs/adr/`](./docs/adr/) — architecture decision records (single package, BCL-only isolation, protocol security rules, quality gate).
- [`docs/diagrams/`](./docs/diagrams/) — C4 context and container diagrams.

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md) and the [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md). Issues and pull requests are welcome.

## License

[MIT](./LICENSE) © Matios SpA.

## 💛 Support

Matios.Security is free and MIT-licensed. If it saves you time, you can support its ongoing development:

[![Donate with PayPal](https://img.shields.io/badge/PayPal-Donate-00457C?logo=paypal&logoColor=white)](https://paypal.me/GContrerasGomez)

<details>
<summary><strong>🪙 Donate with crypto</strong></summary>

<br>

| Network | Address |
|---|---|
| **Ethereum / EVM** (ETH, USDC, …) | `0x5ea6F302Fb8a9865540FfCC42F7264c996532dC3` |
| **Bitcoin** (native SegWit) | `bc1qv43are3facy6lyuzp5qpdqpt8x7tcz2cx3aspe` |
| **Solana** (SOL, SPL) | `BYtfMGEoxBLf5DMPoLyebUJpEh1hW9jGEvjiaEiuRmjw` |
| **TRON** (USDT-TRC20) | `TFHuJKpPNZcdEPsfCknDpvY6CzQbpWYGUv` |

</details>

Every contribution helps keep the project maintained — thank you 🙏

## Español

¿Prefieres español? Lee la [guía de inicio en español](./README.es.md).

---

<p align="center">
  <strong>Matios.Security</strong><br>
  Pure BCL &nbsp;·&nbsp; Strict JOSE profile &nbsp;·&nbsp; Real conformance.
</p>
