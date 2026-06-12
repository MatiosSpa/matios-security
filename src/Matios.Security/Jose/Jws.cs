using System.Security.Cryptography;
using System.Text;

namespace Matios.Security.Jose;

/// <summary>
/// JWS Compact Serialization (RFC 7515 §3.1): signing and verification.
/// MVP: <c>HS256</c>, enough for Nested JWT.
/// </summary>
public static class Jws
{
    /// <summary>Signs the payload and returns the compact JWS (3 segments).</summary>
    public static string Sign(ReadOnlySpan<byte> payload, SymmetricJoseKey key,
                              JwsSignOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(key);
        options ??= new JwsSignOptions();

        byte[] headerJson = JoseHeaderWriter.Write(
            options.Algorithm.ToHeaderValue(),
            encryption: null,
            key.KeyId,
            options.Type,
            options.ContentType,
            options.ExtraHeaders);

        string signingInput = Base64Url.Encode(headerJson) + "." + Base64Url.Encode(payload);
        byte[] signature = HMACSHA256.HashData(key.Material, Encoding.ASCII.GetBytes(signingInput));

        return signingInput + "." + Base64Url.Encode(signature);
    }

    /// <summary>
    /// Verifies a compact JWS. The header's <c>alg</c> must be in the caller's
    /// whitelist; the HMAC comparison is constant-time.
    /// </summary>
    public static JwsVerifyResult Verify(string token, SymmetricJoseKey key,
                                         JwsVerifyOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(key);
        options ??= new JwsVerifyOptions();

        if (string.IsNullOrEmpty(token))
        {
            throw new JoseException(JoseFailureCode.MalformedToken);
        }

        if (token.Length > options.MaxTokenBytes)
        {
            throw new JoseException(JoseFailureCode.TokenTooLarge);
        }

        string[] segments = token.Split('.');
        if (segments.Length != 3)
        {
            throw new JoseException(JoseFailureCode.MalformedToken);
        }

        byte[] headerJson = Base64Url.Decode(segments[0]);
        JoseHeader header = JoseHeader.Parse(headerJson);   // validates zip/crit/alg presence

        if (!IsAccepted(header.Algorithm, options.AcceptedAlgorithms))
        {
            throw new JoseException(JoseFailureCode.AlgorithmNotAccepted);
        }

        byte[] payload = Base64Url.Decode(segments[1]);
        byte[] signature = Base64Url.Decode(segments[2]);

        string signingInput = segments[0] + "." + segments[1];
        byte[] expected = HMACSHA256.HashData(key.Material, Encoding.ASCII.GetBytes(signingInput));

        if (!CryptographicOperations.FixedTimeEquals(expected, signature))
        {
            throw new JoseException(JoseFailureCode.SignatureInvalid);
        }

        return new JwsVerifyResult(payload, header);
    }

    private static bool IsAccepted(string headerValue, IReadOnlyCollection<JwsAlgorithm> accepted)
    {
        foreach (JwsAlgorithm algorithm in accepted)
        {
            if (string.Equals(algorithm.ToHeaderValue(), headerValue, StringComparison.Ordinal))
            {
                return true;
            }
        }
        return false;
    }
}

/// <summary>JWS sign options.</summary>
public sealed class JwsSignOptions
{
    /// <summary>Signature algorithm. Default and only MVP value: <see cref="JwsAlgorithm.Hs256"/>.</summary>
    public JwsAlgorithm Algorithm { get; init; } = JwsAlgorithm.Hs256;

    /// <summary><c>typ</c> header (e.g. "JWT").</summary>
    public string? Type { get; init; }

    /// <summary><c>cty</c> header.</summary>
    public string? ContentType { get; init; }

    /// <summary>Additional headers. Cannot override <c>alg</c>/<c>enc</c>/<c>zip</c>/<c>crit</c> nor the dedicated options.</summary>
    public IReadOnlyDictionary<string, string>? ExtraHeaders { get; init; }
}

/// <summary>JWS verify options.</summary>
public sealed class JwsVerifyOptions
{
    /// <summary>Accepted signature algorithms. Default: MVP set.</summary>
    public IReadOnlyCollection<JwsAlgorithm> AcceptedAlgorithms { get; init; } = [JwsAlgorithm.Hs256];

    /// <summary>Defensive token size limit.</summary>
    public int MaxTokenBytes { get; init; } = 64 * 1024;
}

/// <summary>Result of a successful JWS verification.</summary>
public sealed class JwsVerifyResult
{
    private string? _payloadUtf8;

    /// <summary>Verified payload.</summary>
    public byte[] Payload { get; }

    /// <summary>Validated protected header.</summary>
    public JoseHeader Header { get; }

    /// <summary>Payload decoded as UTF-8 (lazy).</summary>
    public string PayloadUtf8 => _payloadUtf8 ??= Encoding.UTF8.GetString(Payload);

    internal JwsVerifyResult(byte[] payload, JoseHeader header)
    {
        Payload = payload;
        Header = header;
    }
}
