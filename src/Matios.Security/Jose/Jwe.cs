using System.Security.Cryptography;
using System.Text;

namespace Matios.Security.Jose;

/// <summary>
/// JWE Compact Serialization (RFC 7516 §3.1): authenticated encryption and decryption.
/// MVP: <c>alg: dir</c> + <c>enc: A256GCM</c>.
/// </summary>
public static class Jwe
{
    private const int NonceSizeInBytes = 12;   // 96 bits (RFC 7518 §5.3)
    private const int TagSizeInBytes = 16;     // 128 bits

    /// <summary>Encrypts the plaintext and returns the compact JWE (5 segments).</summary>
    public static string Encrypt(ReadOnlySpan<byte> plaintext, SymmetricJoseKey key,
                                 JweEncryptOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(key);
        options ??= new JweEncryptOptions();

        // MVP: dir + A256GCM. The CEK IS the shared key (RFC 7518 §4.5).
        key.EnsureExactSize(256);

        byte[] headerJson = JoseHeaderWriter.Write(
            options.Algorithm.ToHeaderValue(),
            options.Encryption.ToHeaderValue(),
            key.KeyId,
            options.Type,
            options.ContentType,
            options.ExtraHeaders);

        string protectedHeader = Base64Url.Encode(headerJson);
        byte[] aad = JoseHeaderWriter.AsciiBytes(protectedHeader);   // RFC 7516 §5.1 step 14

        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSizeInBytes);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[TagSizeInBytes];

        using (var aes = new AesGcm(key.Material, TagSizeInBytes))
        {
            aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);
        }

        // dir → the Encrypted Key segment travels empty.
        return string.Concat(
            protectedHeader, ".",
            string.Empty, ".",
            Base64Url.Encode(nonce), ".",
            Base64Url.Encode(ciphertext), ".",
            Base64Url.Encode(tag));
    }

    /// <summary>Encrypts a UTF-8 string and returns the compact JWE.</summary>
    public static string EncryptUtf8(string plaintext, SymmetricJoseKey key,
                                     JweEncryptOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        return Encrypt(Encoding.UTF8.GetBytes(plaintext), key, options);
    }

    /// <summary>
    /// Decrypts a compact JWE. The header NEVER decides on its own:
    /// <c>alg</c>/<c>enc</c> must be in the <paramref name="options"/>
    /// whitelists (anti algorithm-confusion).
    /// </summary>
    public static JweDecryptResult Decrypt(string token, SymmetricJoseKey key,
                                           JweDecryptOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(key);
        options ??= new JweDecryptOptions();

        if (string.IsNullOrEmpty(token))
        {
            throw new JoseException(JoseFailureCode.MalformedToken);
        }

        if (token.Length > options.MaxTokenBytes)
        {
            throw new JoseException(JoseFailureCode.TokenTooLarge);
        }

        string[] segments = token.Split('.');
        if (segments.Length != 5)
        {
            throw new JoseException(JoseFailureCode.MalformedToken);
        }

        byte[] headerJson = Base64Url.Decode(segments[0]);
        JoseHeader header = JoseHeader.Parse(headerJson);   // validates zip/crit/alg presence

        if (!IsAccepted(header.Algorithm, options.AcceptedAlgorithms) ||
            header.Encryption is null ||
            !IsAccepted(header.Encryption, options.AcceptedEncryptions))
        {
            throw new JoseException(JoseFailureCode.AlgorithmNotAccepted);
        }

        // dir → the Encrypted Key MUST be empty (RFC 7518 §4.5).
        if (segments[1].Length != 0)
        {
            throw new JoseException(JoseFailureCode.MalformedToken);
        }

        key.EnsureExactSize(256);

        byte[] nonce = Base64Url.Decode(segments[2]);
        byte[] ciphertext = Base64Url.Decode(segments[3]);
        byte[] tag = Base64Url.Decode(segments[4]);

        if (nonce.Length != NonceSizeInBytes || tag.Length != TagSizeInBytes)
        {
            throw new JoseException(JoseFailureCode.MalformedToken);
        }

        byte[] aad = JoseHeaderWriter.AsciiBytes(segments[0]);
        byte[] plaintext = new byte[ciphertext.Length];

        try
        {
            using var aes = new AesGcm(key.Material, TagSizeInBytes);
            aes.Decrypt(nonce, ciphertext, tag, plaintext, aad);
        }
        catch (CryptographicException)
        {
            throw new JoseException(JoseFailureCode.DecryptionFailed);
        }

        return new JweDecryptResult(plaintext, header);
    }

    private static bool IsAccepted(string headerValue, IReadOnlyCollection<JweAlgorithm> accepted)
    {
        foreach (JweAlgorithm algorithm in accepted)
        {
            if (string.Equals(algorithm.ToHeaderValue(), headerValue, StringComparison.Ordinal))
            {
                return true;
            }
        }
        return false;
    }

    private static bool IsAccepted(string headerValue, IReadOnlyCollection<JweEncryption> accepted)
    {
        foreach (JweEncryption encryption in accepted)
        {
            if (string.Equals(encryption.ToHeaderValue(), headerValue, StringComparison.Ordinal))
            {
                return true;
            }
        }
        return false;
    }
}

/// <summary>JWE issue options. <c>zip</c> is not configurable: rejected by design.</summary>
public sealed class JweEncryptOptions
{
    /// <summary>Key management. Default and only MVP value: <see cref="JweAlgorithm.Dir"/>.</summary>
    public JweAlgorithm Algorithm { get; init; } = JweAlgorithm.Dir;

    /// <summary>Content encryption. Default and only MVP value: <see cref="JweEncryption.A256Gcm"/>.</summary>
    public JweEncryption Encryption { get; init; } = JweEncryption.A256Gcm;

    /// <summary><c>typ</c> header (e.g. "JWT" in Nested JWT).</summary>
    public string? Type { get; init; }

    /// <summary><c>cty</c> header (e.g. "JWT" in Nested JWT).</summary>
    public string? ContentType { get; init; }

    /// <summary>Additional headers. Cannot override <c>alg</c>/<c>enc</c>/<c>zip</c>/<c>crit</c> nor the dedicated options.</summary>
    public IReadOnlyDictionary<string, string>? ExtraHeaders { get; init; }
}

/// <summary>JWE decrypt options. The caller's whitelists rule over the header.</summary>
public sealed class JweDecryptOptions
{
    /// <summary>Accepted key management algorithms. Default: MVP set.</summary>
    public IReadOnlyCollection<JweAlgorithm> AcceptedAlgorithms { get; init; } = [JweAlgorithm.Dir];

    /// <summary>Accepted content encryption algorithms. Default: MVP set.</summary>
    public IReadOnlyCollection<JweEncryption> AcceptedEncryptions { get; init; } = [JweEncryption.A256Gcm];

    /// <summary>Defensive token size limit.</summary>
    public int MaxTokenBytes { get; init; } = 64 * 1024;
}

/// <summary>Result of a successful JWE decryption.</summary>
public sealed class JweDecryptResult
{
    private string? _plaintextUtf8;

    /// <summary>Decrypted and authenticated plaintext.</summary>
    public byte[] Plaintext { get; }

    /// <summary>Validated protected header.</summary>
    public JoseHeader Header { get; }

    /// <summary>Plaintext decoded as UTF-8 (lazy).</summary>
    public string PlaintextUtf8 => _plaintextUtf8 ??= Encoding.UTF8.GetString(Plaintext);

    internal JweDecryptResult(byte[] plaintext, JoseHeader header)
    {
        Plaintext = plaintext;
        Header = header;
    }
}
