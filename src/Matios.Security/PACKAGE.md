# Matios.Security

**Dependency-free JOSE + JWT for .NET — built only on the BCL.**

JWE (RFC 7516) · JWS (RFC 7515) · JWT (RFC 7519) · Nested JWT

## What is JOSE?

**JOSE** — *JSON Object Signing and Encryption* — is the IETF standards family behind modern web tokens:

| RFC | Piece | What it does |
| --- | --- | --- |
| 7515 | **JWS** | Signed content — integrity + authenticity |
| 7516 | **JWE** | Encrypted content — confidentiality |
| 7517 | **JWK** | Keys represented as JSON |
| 7518 | **JWA** | The algorithm catalog the others reference |
| 7519 | **JWT** | Claims (tokens) built on top of JWS/JWE |

## Why Matios.Security

- **Zero dependencies.** Built only on `System.Security.Cryptography` and `System.Text.Json` — nothing else, ever.
- **It encrypts what Microsoft's stack cannot.** `Microsoft.IdentityModel.*` can *decrypt* JWE `A256GCM` but cannot *issue* it (`IDX10715`), and cannot decrypt it at all on Linux/macOS. This library issues and consumes `dir`+`A256GCM` on every platform — and interops with Microsoft.IdentityModel for validation (covered by tests).
- **Strict by design.** Closed algorithm enums (no magic strings, no `alg:"none"`), caller-side algorithm whitelists — the token header never decides on its own. `zip` rejected, unknown `crit` rejected, duplicate header/claim names rejected.
- **Anti-oracle errors.** One generic exception; the fine-grained failure code is for server-side logging only.

## Quick start

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
    .Claim("RoleId", 7)                     // private claims: any JSON-serializable value
    .SignWith(signingKey)
    .EncryptWith(encryptionKey)             // JWE dir+A256GCM outside, signature inside
    .Create();

// Validation
JwtClaims claims = JwtValidator.Validate(token, new JwtValidationParameters
{
    SigningKey = signingKey,
    DecryptionKey = encryptionKey,   // set => token MUST be JWE (no silent downgrade)
    ValidIssuer = "my-platform",
    ValidAudience = "my-api"
});

long roleId = claims.GetClaim<long>("RoleId");
```

## Scope — deliberately minimal

| Supported (v0.x) | Not supported, by design |
| --- | --- |
| JWE Compact `dir` + `A256GCM` | `zip` (compression oracle) — rejected, ever |
| JWS Compact `HS256` | `alg: "none"` — does not exist in the API |
| Nested JWT (`cty:"JWT"`) | JSON Serialization / multi-recipient |
| JWK `kty:"oct"` key input | `RSA-OAEP` / `ECDH-ES` / `A256KW` / `RS256` (future, if real interop demands them) |

Everything implemented is conformant and covered by tests; everything outside the profile is cleanly rejected.

## Conformance evidence

- Official **RFC 7515 Appendix A.1** HS256 vector (accept + tampered-reject).
- **Bidirectional interop** against `Microsoft.IdentityModel.JsonWebTokens` (an independent implementation), with canary tests pinning its two `A256GCM` limitations.
- **Strict negative suite**: `zip`, `crit`, algorithm confusion, `none`, tampered AAD/tag, duplicate names, oversized tokens, undersized keys.
- **49 tests, all green on Ubuntu and Windows, on every CI run.**

## Links

- Repository, full docs and usage guide: https://github.com/MatiosSpa/matios-security
- License: MIT © Matios SpA
