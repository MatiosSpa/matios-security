using System.Security.Cryptography;

namespace Matios.Security.Jose;

/// <summary>
/// Symmetric key for JOSE operations (HS256 signing and dir+A256GCM encryption).
/// Immutable and thread-safe. The key material is never exposed through a getter
/// and is wiped from memory on dispose.
/// </summary>
public sealed class SymmetricJoseKey : IDisposable
{
    private const int MinimumSizeInBytes = 32;

    private readonly byte[] _material;
    private bool _disposed;

    /// <summary>Optional key identifier; travels as <c>kid</c> in the header.</summary>
    public string? KeyId { get; }

    /// <summary>Key size in bits.</summary>
    public int SizeInBits { get; }

    private SymmetricJoseKey(byte[] material, string? keyId)
    {
        _material = material;
        KeyId = keyId;
        SizeInBits = material.Length * 8;
    }

    /// <summary>
    /// Creates the key from raw bytes. Minimum 256 bits (required both by
    /// HS256 — RFC 7518 §3.2 — and by A256GCM). Takes a defensive copy.
    /// </summary>
    public static SymmetricJoseKey FromBytes(ReadOnlySpan<byte> key, string? keyId = null)
    {
        if (key.Length < MinimumSizeInBytes)
        {
            throw new JoseException(JoseFailureCode.InvalidKey);
        }

        return new SymmetricJoseKey(key.ToArray(), keyId);
    }

    /// <summary>Creates the key from the <c>k</c> value of a JWK <c>kty: "oct"</c> (base64url, RFC 7517 §6.4.1).</summary>
    public static SymmetricJoseKey FromBase64Url(string k, string? keyId = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(k);

        byte[] material;
        try
        {
            material = Base64Url.Decode(k);
        }
        catch (JoseException)
        {
            throw new JoseException(JoseFailureCode.InvalidKey);
        }

        if (material.Length < MinimumSizeInBytes)
        {
            CryptographicOperations.ZeroMemory(material);
            throw new JoseException(JoseFailureCode.InvalidKey);
        }

        return new SymmetricJoseKey(material, keyId);
    }

    /// <summary>Internal access to the material; never exposed outside the assembly.</summary>
    internal ReadOnlySpan<byte> Material
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _material;
        }
    }

    /// <summary>Enforces an exact size (e.g. 256 bits for A256GCM) at the point of use.</summary>
    internal void EnsureExactSize(int sizeInBits)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (SizeInBits != sizeInBits)
        {
            throw new JoseException(JoseFailureCode.InvalidKey);
        }
    }

    /// <summary>Wipes the key material from memory.</summary>
    public void Dispose()
    {
        if (!_disposed)
        {
            CryptographicOperations.ZeroMemory(_material);
            _disposed = true;
        }
    }
}
