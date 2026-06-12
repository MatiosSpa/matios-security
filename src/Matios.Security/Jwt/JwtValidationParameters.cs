using Matios.Security.Jose;

namespace Matios.Security.Jwt;

/// <summary>JWT validation parameters.</summary>
public sealed class JwtValidationParameters
{
    /// <summary>Signature verification key. Mandatory.</summary>
    public SymmetricJoseKey? SigningKey { get; init; }

    /// <summary>
    /// JWE decryption key. When set, the token MUST be an encrypted Nested JWT —
    /// a plain JWS is rejected (no silent downgrade).
    /// </summary>
    public SymmetricJoseKey? DecryptionKey { get; init; }

    /// <summary>Expected issuer (<c>iss</c>). Null = do not validate the issuer.</summary>
    public string? ValidIssuer { get; init; }

    /// <summary>Expected audience (<c>aud</c>). Null = do not validate the audience.</summary>
    public string? ValidAudience { get; init; }

    /// <summary>Clock tolerance for <c>exp</c>/<c>nbf</c>.</summary>
    public TimeSpan ClockSkew { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>When true (default), a token without <c>exp</c> is rejected.</summary>
    public bool RequireExpiration { get; init; } = true;
}
