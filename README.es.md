<p align="center">
  <img src="./assets/icon.png" alt="Matios.Security" width="160"/>
</p>

<h1 align="center">Matios.Security</h1>

<p align="center">
  JOSE + JWT para .NET sin dependencias — construido solo sobre la BCL.<br>
  JWE (RFC 7516) &nbsp;·&nbsp; JWS (RFC 7515) &nbsp;·&nbsp; JWT (RFC 7519) &nbsp;·&nbsp; Nested JWT
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="Licencia: MIT">
  <img src="https://img.shields.io/badge/dependencies-0-brightgreen.svg" alt="Cero dependencias">
  <img src="https://img.shields.io/badge/.NET-10.0-512BD4.svg" alt=".NET 10">
  <img src="https://github.com/MatiosSpa/matios-security/actions/workflows/ci.yml/badge.svg" alt="CI">
  &nbsp;·&nbsp; <a href="./README.md">English</a>
</p>

---

## ¿Qué es JOSE?

**JOSE** — *JSON Object Signing and Encryption* (firma y cifrado de objetos JSON) — es la familia de estándares de la IETF detrás de los tokens web modernos:

| RFC | Pieza | Qué hace |
|---|---|---|
| [7515](https://www.rfc-editor.org/rfc/rfc7515) | **JWS** | Contenido firmado — integridad + autenticidad |
| [7516](https://www.rfc-editor.org/rfc/rfc7516) | **JWE** | Contenido cifrado — confidencialidad |
| [7517](https://www.rfc-editor.org/rfc/rfc7517) | **JWK** | Claves representadas como JSON |
| [7518](https://www.rfc-editor.org/rfc/rfc7518) | **JWA** | El catálogo de algoritmos que las demás referencian |
| [7519](https://www.rfc-editor.org/rfc/rfc7519) | **JWT** | Claims (tokens) construidos sobre JWS/JWE |

---

## Por qué Matios.Security

La mayoría de los stacks JWT para .NET son pesados, están fragmentados en paquetes interdependientes, o no pueden realmente *cifrar* tokens con AEAD moderno.

Matios.Security toma otro camino:

| | |
|---|---|
| **Cero dependencias** | Construido solo sobre `System.Security.Cryptography` y `System.Text.Json` — nada más, nunca |
| **Cifra lo que el stack de Microsoft no puede** | `Microsoft.IdentityModel.*` puede *descifrar* JWE `A256GCM` pero no puede *emitirlo* (`IDX10715`). Esta librería emite y consume `dir`+`A256GCM` — e interopera con Microsoft para la validación |
| **Estricto por diseño** | Enums cerrados de algoritmos (sin strings mágicos, sin `alg:"none"`), whitelists del lado del consumidor — el header del token nunca decide solo |
| **Errores anti-oracle** | Una sola excepción genérica; el código fino de fallo es solo para logging del lado servidor |
| **Fácil de auditar** | Un puñado de archivos chicos y legibles — un perfil estricto y testeable de las RFC JOSE |

---

## Inicio rápido

```
dotnet add package Matios.Security
```

### Uso mínimo

```csharp
using Matios.Security.Jose;
using Matios.Security.Jwt;

// Usa claves DISTINTAS para firmar y cifrar. Mínimo 256 bits.
SymmetricJoseKey signingKey = SymmetricJoseKey.FromBase64Url(signingKeyB64, "sig-2026");
SymmetricJoseKey encryptionKey = SymmetricJoseKey.FromBase64Url(encryptionKeyB64, "enc-2026");

// JWT firmado (JWS) — agrega UNA línea para volverlo cifrado (Nested JWT)
string token = new JwtBuilder()
    .Issuer("mi-plataforma")
    .Audience("mi-api")
    .Subject(userId)
    .IdAuto()
    .Lifetime(TimeSpan.FromMinutes(30))
    .Claim("RoleId", 7)                          // private claims: cualquier valor JSON-serializable
    .Claim("companyIds", new List<long> { 1, 4, 9 })
    .SignWith(signingKey)
    .EncryptWith(encryptionKey)                  // ← JWE dir+A256GCM afuera, firma adentro
    .Create();

// Validación
JwtClaims claims = JwtValidator.Validate(token, new JwtValidationParameters
{
    SigningKey = signingKey,
    DecryptionKey = encryptionKey,   // poblada ⇒ el token DEBE ser JWE (sin downgrade silencioso)
    ValidIssuer = "mi-plataforma",
    ValidAudience = "mi-api"
});

long roleId = claims.GetClaim<long>("RoleId");
```

---

## Compilar localmente

Sin tooling especial — solo el SDK de .NET 10:

```bash
dotnet build src/Matios.Security/Matios.Security.csproj
dotnet test tests/Matios.Security.Tests/Matios.Security.Tests.csproj
dotnet pack src/Matios.Security/Matios.Security.csproj -o artifacts
```

---

## Modelo de seguridad

Matios.Security implementa un **perfil estricto** de las RFC JOSE:

- **Whitelists del consumidor** — al descifrar/verificar, *tú* declaras los `alg`/`enc` aceptados; el header del token nunca decide solo (anti algorithm-confusion).
- **`alg: "none"` no existe** en la API. Nunca existirá.
- **`zip` rechazado** al emitir y al parsear (clase compression-oracle, CRIME/BREACH).
- **`crit` desconocido rechazado** (RFC 7515 §4.1.11).
- **Nombres duplicados de header/claims rechazados** (RFC 7515 §4 / RFC 7519 §4, opción estricta).
- **Cifrar sin firmar está prohibido** — un JWE `dir` sin firma interna no autentica al emisor.
- **Comparación HMAC en tiempo constante**, IV fresco de 96 bits por token desde un CSPRNG, material de clave borrado al disponer.

---

## Superficie de la API

### `Matios.Security.Jose`
`Jwe` (Encrypt / Decrypt) · `Jws` (Sign / Verify) · `SymmetricJoseKey` · `JoseHeader` · `JoseException` + `JoseFailureCode` · records de options/results

### `Matios.Security.Jwt`
`JwtBuilder` (emisión fluida, claims dinámicos, Nested JWT) · `JwtValidator` (Validate / TryValidate) · `JwtClaims` (lectura tipada de claims) · `JwtValidationParameters`

---

## Modelo de errores

Todo fallo lanza la única `JoseException` con un mensaje fijo y genérico (anti-oracle). El detalle vive en `JoseException.FailureCode` (`TokenExpired`, `SignatureInvalid`, `AlgorithmNotAccepted`, …) y es **solo para logging del lado servidor** — al cliente siempre se le responde genérico.

---

## Alcance — deliberadamente mínimo

| Soportado (v0.x) | No soportado, por diseño |
|---|---|
| JWE Compact `dir` + `A256GCM` | `zip` (compression oracle) — rechazado, siempre |
| JWS Compact `HS256` | `alg: "none"` — no existe en la API |
| Nested JWT (`cty:"JWT"`) | JSON Serialization / multi-recipient |
| Entrada de clave JWK `kty:"oct"` | `RSA-OAEP` / `ECDH-ES` / `A256KW` / `A128CBC-HS256` / `RS256` (futuro, si una interop real los exige) |

Todo lo implementado es conforme y está cubierto por tests; todo lo que queda fuera del perfil se **rechaza limpiamente** — el comportamiento conforme para una implementación que no soporta una feature.

---

## Evidencia de conformidad

- Vector oficial HS256 del **Apéndice A.1 de la RFC 7515** (aceptación + rechazo con firma alterada).
- **Interop**: los tokens emitidos por esta librería los descifra y valida `Microsoft.IdentityModel.JsonWebTokens` (implementación independiente), y viceversa para JWS. Un test canario fija la limitación `IDX10715` de Microsoft al emitir.
- **Suite negativa estricta**: `zip`, `crit`, confusión de algoritmos, `none`, Encrypted Key no vacío con `dir`, AAD/tag alterados, nombres duplicados, headers con BOM, tokens sobredimensionados, claves cortas.
- **49 tests, todos verdes, en cada corrida del CI.**

---

## Principios de diseño

- BCL-only, para siempre — la flecha de dependencia apunta *hacia* este paquete, nunca desde él
- Un paquete; la familia vive en namespaces, no en ids de paquete
- Perfil estricto antes que superficie amplia — lo no soportado se rechaza limpiamente
- El consumidor decide los algoritmos aceptados, nunca el token
- Errores genéricos hacia afuera, precisos hacia adentro
- Código chico, legible y amigable a la auditoría

Ver [`CONTRIBUTING.md`](./CONTRIBUTING.md) para las convenciones completas.

---

## Estado

Matios.Security está en **v0.x** — el perfil implementado es estable, testeado y verificado por interop; la API pública aún puede evolucionar antes de `1.0.0`.

## Licencia

[MIT](./LICENSE) © Matios SpA.

---

<p align="center">
  <strong>Matios.Security</strong><br>
  BCL pura &nbsp;·&nbsp; Perfil JOSE estricto &nbsp;·&nbsp; Conformidad real.
</p>
