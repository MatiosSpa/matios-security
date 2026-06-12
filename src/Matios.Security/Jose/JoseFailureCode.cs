namespace Matios.Security.Jose;

/// <summary>
/// Internal failure code of a JOSE/JWT operation. Intended ONLY for server-side
/// logging by the consumer: the <see cref="JoseException"/> message is
/// deliberately generic (anti-oracle) and this code carries the detail.
/// </summary>
public enum JoseFailureCode
{
    /// <summary>The token does not have the expected compact form (segments, base64url or JSON invalid).</summary>
    MalformedToken,

    /// <summary>The header's <c>alg</c>/<c>enc</c> is not in the caller-declared whitelist.</summary>
    AlgorithmNotAccepted,

    /// <summary>The header carries <c>zip</c>: compression is rejected by design (compression oracle).</summary>
    ZipRejected,

    /// <summary>The header carries <c>crit</c> with parameters this library does not support.</summary>
    UnknownCritical,

    /// <summary>The key is invalid for the operation (size, absence or disposed state).</summary>
    InvalidKey,

    /// <summary>AEAD decryption failed (invalid tag, tampered AAD or wrong key material).</summary>
    DecryptionFailed,

    /// <summary>The JWS signature does not verify against the provided key.</summary>
    SignatureInvalid,

    /// <summary>The token exceeds the configured defensive size limit.</summary>
    TokenTooLarge,

    /// <summary>The header is valid JSON but violates the protocol (missing <c>alg</c>, duplicate names, expected <c>cty</c>, etc.).</summary>
    HeaderInvalid,

    /// <summary>The claim exists but its value cannot be deserialized to the requested type.</summary>
    ClaimTypeMismatch,

    /// <summary>The <c>exp</c> claim is in the past (clock skew considered).</summary>
    TokenExpired,

    /// <summary>The <c>nbf</c> claim is in the future (clock skew considered).</summary>
    TokenNotYetValid,

    /// <summary>The <c>iss</c> claim does not match the expected issuer.</summary>
    IssuerMismatch,

    /// <summary>The <c>aud</c> claim does not contain the expected audience.</summary>
    AudienceMismatch,

    /// <summary>A required claim is missing (e.g. <c>exp</c> when validation demands it).</summary>
    MissingClaim
}
