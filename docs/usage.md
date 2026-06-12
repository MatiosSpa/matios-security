# Matios.Security — Usage guide

Practical manual for consuming developers. The README covers the quick start;
this guide goes deeper into key handling, claims strategy and error handling.

## 1. Keys

```csharp
// From raw bytes (minimum 256 bits; for JWE A256GCM: exactly 256)
SymmetricJoseKey key = SymmetricJoseKey.FromBytes(bytes32, keyId: "sig-2026");

// From base64url (the "k" field of a JWK kty:"oct")
SymmetricJoseKey key = SymmetricJoseKey.FromBase64Url(base64UrlString, "enc-2026");
```

Rules:

- Keys are immutable and thread-safe; the material cannot be read back and
  `Dispose()` wipes it from memory.
- Use **different** keys for signing and encryption. Reusing one key for two
  purposes weakens both.
- The optional `keyId` travels as `kid` in the header — useful for rotation.

## 2. Claims strategy ("claims instead of a DB round-trip")

Private claims are the standard place for data **you** decide to embed
(`RoleId`, permission bitmasks, tenant ids). Two physics constraints to keep
in mind:

- **Size**: the token travels on every request; the practical cookie limit is
  ~4 KB. IDs, bitmasks and short ciphers: great. Lists of hundreds of
  objects: no. (And `zip` is rejected by design, so there is no compression
  escape hatch — on purpose.)
- **Staleness**: a claim freezes at issue time. Embed stable data; data that
  changes by the minute belongs in your DB/cache. A refresh-token rotation
  scheme naturally re-freshes claims at each rotation.

With Nested JWT (`EncryptWith`), claims are also **confidential** — you can
embed values that would be readable in a plain JWS.

```csharp
.Claim("RoleId", 7)
.Claim("permCipher", accessBitmaskBase64)        // 100 booleans ≈ 17 bytes as bitmask
.Claim("context", new { tenant = "x", level = 3 })
```

Typed reads on the other side:

```csharp
long roleId = claims.GetClaim<long>("RoleId");
if (claims.TryGetClaim("permCipher", out string? cipher)) { ... }
```

- Absent claim → `GetClaim` returns `default`, `TryGetClaim` returns false.
- Type mismatch → `JoseException` with `ClaimTypeMismatch`.
- The 7 registered claims (`iss/sub/aud/exp/nbf/iat/jti`) cannot be set via
  `Claim()` — use the dedicated builder methods.

## 3. Validation posture

```csharp
var parameters = new JwtValidationParameters
{
    SigningKey = signingKey,        // mandatory
    DecryptionKey = encryptionKey,  // set ⇒ token MUST be a JWE (no downgrade)
    ValidIssuer = "my-platform",    // null = skip issuer check
    ValidAudience = "my-api",       // null = skip audience check
    ClockSkew = TimeSpan.FromSeconds(60),
    RequireExpiration = true        // default: tokens without exp are rejected
};
```

Key behaviors:

- `DecryptionKey` set + plain JWS arrives → **rejected** (`AlgorithmNotAccepted`).
  This is what makes an "encrypted tokens only" policy actually enforceable.
- JWE arrives but no `DecryptionKey` configured → rejected.
- `aud` may be a string or an array in the token; both match correctly.

## 4. Error handling

All failures throw `JoseException` with an identical generic message. Log the
`FailureCode` server-side; never forward it to clients.

| Code | Meaning |
|---|---|
| `MalformedToken` | Structure/base64url/JSON invalid (incl. duplicate claim names) |
| `AlgorithmNotAccepted` | `alg`/`enc` outside whitelist, or JWS downgrade when JWE expected |
| `ZipRejected` / `UnknownCritical` | Header carries `zip` or `crit` — rejected by design |
| `InvalidKey` | Key too short / missing / wrong size for the operation |
| `DecryptionFailed` / `SignatureInvalid` | Crypto does not verify (tag/AAD/signature/key) |
| `TokenExpired` / `TokenNotYetValid` / `MissingClaim` | Temporal validation |
| `IssuerMismatch` / `AudienceMismatch` | `iss`/`aud` do not match |
| `ClaimTypeMismatch` | Claim exists but does not deserialize to the requested type |
| `HeaderInvalid` | Protocol violation in the header (missing `alg`, duplicates, expected `cty`, …) |
| `TokenTooLarge` | Exceeds `MaxTokenBytes` |

## 5. ASP.NET Core integration sketch

`JsonWebTokenHandler` (Microsoft) validates this library's tokens directly —
including Nested JWE — so the standard `AddJwtBearer` setup works by adding
`TokenDecryptionKey`:

```csharp
options.TokenValidationParameters = new TokenValidationParameters
{
    IssuerSigningKey = new SymmetricSecurityKey(signingKeyBytes),
    TokenDecryptionKey = new SymmetricSecurityKey(encryptionKeyBytes),
    ValidIssuer = "my-platform",
    ValidAudience = "my-api"
};
```

Or validate manually with `JwtValidator` in your own middleware for full
control of the whitelists.

## 6. Known interop limitations (Microsoft.IdentityModel)

Two limitations of Microsoft's stack — both pinned by canary tests in CI:

1. **Cannot issue** JWE with `A256GCM` on any platform (`IDX10715`; it only
   decrypts it).
2. **Cannot decrypt** `A256GCM` on Linux/macOS
   (`algorithmNotSupportedByCryptoProvider`) — Windows only.

Matios.Security issues **and** consumes `dir`+`A256GCM` on every platform
(the BCL `AesGcm` is cross-platform). If another .NET system must exchange
encrypted tokens with yours — especially on Linux — have it use this same
package on both ends.
