# Contributing to Matios.Security

Thanks for your interest. This library is small on purpose — contributions are
welcome as long as they respect the rules that keep it small, strict and
auditable.

## Non-negotiable rules

1. **BCL-only.** No `PackageReference` may ever be added to
   `src/Matios.Security/`. The package depends exclusively on
   `System.Security.Cryptography` and `System.Text.Json`. (Test-project
   dependencies are fine — that's where interop verification lives.)
2. **Strict profile.** Features outside the supported profile are *cleanly
   rejected*, not half-implemented. If you add an algorithm, it enters the
   closed enums, the caller-side whitelists, and the negative test suite —
   all three.
3. **No `alg: "none"`, no `zip`. Ever.** Pull requests adding either will be
   declined regardless of justification.
4. **Anti-oracle errors.** All failures throw `JoseException` with the fixed
   generic message; detail goes only into `JoseFailureCode`.
5. **Every security rule has a test.** A change to parsing/validation logic
   without its negative test is incomplete.

## Quality gate (applies to every PR)

- `dotnet build` green with `TreatWarningsAsErrors` (XML docs required on all
  public members).
- `dotnet test` fully green — including the RFC 7515 A.1 vector, the
  Microsoft.IdentityModel interop tests, and the strict negative suite.
- New algorithms require: official RFC test vectors when they exist, interop
  coverage when an independent implementation supports them, and negative
  tests for their failure modes.

## Style

- C# with nullable enabled; no abbreviations in public names.
- Async methods do not carry an `Async` suffix (the `Task` signature already
  says it).
- Keep files small and single-purpose — this library is meant to be read.

## Development flow

```bash
dotnet build src/Matios.Security/Matios.Security.csproj
dotnet test tests/Matios.Security.Tests/Matios.Security.Tests.csproj
```

Open an issue first for anything beyond a bug fix — scope discussions before
code save everyone time, especially given rule 2.
