namespace Matios.Security.Jose;

/// <summary>
/// Supported JWE key management algorithms (RFC 7518 §4).
/// <c>none</c> does not exist and never will in this API.
/// </summary>
public enum JweAlgorithm
{
    /// <summary>Direct Encryption (RFC 7518 §4.5): the shared key IS the CEK; the Encrypted Key segment travels empty.</summary>
    Dir
}

/// <summary>Supported JWE content encryption algorithms (RFC 7518 §5).</summary>
public enum JweEncryption
{
    /// <summary>AES-256 in GCM mode (RFC 7518 §5.3). Requires a key of exactly 256 bits.</summary>
    A256Gcm
}

/// <summary>Supported JWS signature algorithms (RFC 7518 §3).</summary>
public enum JwsAlgorithm
{
    /// <summary>HMAC with SHA-256 (RFC 7518 §3.2). Requires a key of at least 256 bits.</summary>
    Hs256
}

/// <summary>Mapping between the closed enums and the RFC header values.</summary>
internal static class AlgorithmNames
{
    internal const string Dir = "dir";
    internal const string A256Gcm = "A256GCM";
    internal const string Hs256 = "HS256";

    internal static string ToHeaderValue(this JweAlgorithm algorithm)
    {
        return algorithm switch
        {
            JweAlgorithm.Dir => Dir,
            _ => throw new JoseException(JoseFailureCode.AlgorithmNotAccepted)
        };
    }

    internal static string ToHeaderValue(this JweEncryption encryption)
    {
        return encryption switch
        {
            JweEncryption.A256Gcm => A256Gcm,
            _ => throw new JoseException(JoseFailureCode.AlgorithmNotAccepted)
        };
    }

    internal static string ToHeaderValue(this JwsAlgorithm algorithm)
    {
        return algorithm switch
        {
            JwsAlgorithm.Hs256 => Hs256,
            _ => throw new JoseException(JoseFailureCode.AlgorithmNotAccepted)
        };
    }
}
