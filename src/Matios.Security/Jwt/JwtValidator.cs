using System.Text.Json;
using Matios.Security.Jose;

namespace Matios.Security.Jwt;

/// <summary>
/// Validates signed (JWS) and encrypted (Nested JWT) tokens. When
/// <see cref="JwtValidationParameters.DecryptionKey"/> is set, the token MUST
/// be a JWE — no silent downgrade to plain JWS.
/// </summary>
public static class JwtValidator
{
    /// <summary>Validates the token and returns its claims. Fails with a generic <see cref="JoseException"/>.</summary>
    public static JwtClaims Validate(string token, JwtValidationParameters parameters)
    {
        ArgumentNullException.ThrowIfNull(parameters);

        if (parameters.SigningKey is null)
        {
            throw new JoseException(JoseFailureCode.InvalidKey);
        }

        if (string.IsNullOrEmpty(token))
        {
            throw new JoseException(JoseFailureCode.MalformedToken);
        }

        int segments = CountSegments(token);
        string innerToken = token;
        JoseHeader? outerHeader = null;

        if (parameters.DecryptionKey is not null)
        {
            // Enforce JWE: a plain JWS when encryption is expected is a downgrade — reject.
            if (segments != 5)
            {
                throw new JoseException(JoseFailureCode.AlgorithmNotAccepted);
            }

            JweDecryptResult decrypted = Jwe.Decrypt(token, parameters.DecryptionKey);

            // Nested JWT (RFC 7519 §5.2): the content must declare cty: "JWT".
            if (!string.Equals(decrypted.Header.ContentType, "JWT", StringComparison.OrdinalIgnoreCase))
            {
                throw new JoseException(JoseFailureCode.HeaderInvalid);
            }

            outerHeader = decrypted.Header;
            innerToken = decrypted.PlaintextUtf8;
        }
        else if (segments == 5)
        {
            // Encrypted token without a decryption key configured.
            throw new JoseException(JoseFailureCode.MalformedToken);
        }

        JwsVerifyResult verified = Jws.Verify(innerToken, parameters.SigningKey);

        JwtClaims claims = ParseClaims(verified, outerHeader);
        ValidateTemporalClaims(claims, parameters);
        ValidateIssuerAndAudience(claims, parameters);

        return claims;
    }

    /// <summary>Exception-free variant: false + failure code instead of throwing.</summary>
    public static bool TryValidate(string token, JwtValidationParameters parameters,
                                   out JwtClaims? claims, out JoseFailureCode? failure)
    {
        try
        {
            claims = Validate(token, parameters);
            failure = null;
            return true;
        }
        catch (JoseException exception)
        {
            claims = null;
            failure = exception.FailureCode;
            return false;
        }
    }

    private static int CountSegments(string token)
    {
        int dots = 0;
        foreach (char c in token)
        {
            if (c == '.')
            {
                dots++;
            }
        }
        return dots + 1;
    }

    private static JwtClaims ParseClaims(JwsVerifyResult verified, JoseHeader? outerHeader)
    {
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(verified.Payload);
        }
        catch (JsonException)
        {
            throw new JoseException(JoseFailureCode.MalformedToken);
        }

        using (document)
        {
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw new JoseException(JoseFailureCode.MalformedToken);
            }

            // RFC 7519 §4: claim names within the Claims Set MUST be unique;
            // this implementation takes the strict option and rejects duplicates.
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (JsonProperty property in document.RootElement.EnumerateObject())
            {
                if (!seen.Add(property.Name))
                {
                    throw new JoseException(JoseFailureCode.MalformedToken);
                }
            }

            // Clone so the payload outlives the document's dispose.
            return new JwtClaims(document.RootElement.Clone(), verified.Header, outerHeader);
        }
    }

    private static void ValidateTemporalClaims(JwtClaims claims, JwtValidationParameters parameters)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;

        if (claims.ExpiresAt is null)
        {
            if (parameters.RequireExpiration)
            {
                throw new JoseException(JoseFailureCode.MissingClaim);
            }
        }
        else if (now > claims.ExpiresAt.Value.Add(parameters.ClockSkew))
        {
            throw new JoseException(JoseFailureCode.TokenExpired);
        }

        if (claims.NotBefore is not null &&
            now < claims.NotBefore.Value.Subtract(parameters.ClockSkew))
        {
            throw new JoseException(JoseFailureCode.TokenNotYetValid);
        }
    }

    private static void ValidateIssuerAndAudience(JwtClaims claims, JwtValidationParameters parameters)
    {
        if (parameters.ValidIssuer is not null &&
            !string.Equals(claims.Issuer, parameters.ValidIssuer, StringComparison.Ordinal))
        {
            throw new JoseException(JoseFailureCode.IssuerMismatch);
        }

        if (parameters.ValidAudience is not null && !AudienceMatches(claims, parameters.ValidAudience))
        {
            throw new JoseException(JoseFailureCode.AudienceMismatch);
        }
    }

    private static bool AudienceMatches(JwtClaims claims, string validAudience)
    {
        if (!claims.Payload.TryGetProperty("aud", out JsonElement element))
        {
            return false;
        }

        if (element.ValueKind == JsonValueKind.String)
        {
            return string.Equals(element.GetString(), validAudience, StringComparison.Ordinal);
        }

        if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement item in element.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.String &&
                    string.Equals(item.GetString(), validAudience, StringComparison.Ordinal))
                {
                    return true;
                }
            }
        }

        return false;
    }
}
