using System.Text.Json;
using Matios.Security.Jose;

namespace Matios.Security.Jwt;

/// <summary>
/// Builds signed JWTs (JWS) and optionally encrypted ones (Nested JWT, RFC 7519
/// §5.2: signature inside, JWE outside with <c>cty: "JWT"</c>). Dynamic claims
/// accept any JSON-serializable value (RFC 7519 §4.3 — private claims).
/// </summary>
public sealed class JwtBuilder
{
    private static readonly string[] RegisteredClaimNames = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"];

    private readonly Dictionary<string, object?> _claims = new(StringComparer.Ordinal);

    private string? _issuer;
    private string? _audience;
    private string? _subject;
    private string? _id;
    private DateTimeOffset? _issuedAt;
    private DateTimeOffset? _notBefore;
    private TimeSpan? _lifetime;

    private SymmetricJoseKey? _signingKey;
    private JwsAlgorithm _signingAlgorithm = JwsAlgorithm.Hs256;
    private SymmetricJoseKey? _encryptionKey;
    private JweEncryption _encryption = JweEncryption.A256Gcm;

    /// <summary><c>iss</c> claim.</summary>
    public JwtBuilder Issuer(string issuer)
    {
        ArgumentException.ThrowIfNullOrEmpty(issuer);
        _issuer = issuer;
        return this;
    }

    /// <summary><c>aud</c> claim.</summary>
    public JwtBuilder Audience(string audience)
    {
        ArgumentException.ThrowIfNullOrEmpty(audience);
        _audience = audience;
        return this;
    }

    /// <summary><c>sub</c> claim.</summary>
    public JwtBuilder Subject(string subject)
    {
        ArgumentException.ThrowIfNullOrEmpty(subject);
        _subject = subject;
        return this;
    }

    /// <summary>Explicit <c>jti</c> claim.</summary>
    public JwtBuilder Id(string jti)
    {
        ArgumentException.ThrowIfNullOrEmpty(jti);
        _id = jti;
        return this;
    }

    /// <summary>Auto-generated <c>jti</c> claim (GUID).</summary>
    public JwtBuilder IdAuto()
    {
        _id = Guid.NewGuid().ToString("N");
        return this;
    }

    /// <summary><c>iat</c> claim. If not called, the moment of <see cref="Create"/> is used.</summary>
    public JwtBuilder IssuedAt(DateTimeOffset moment)
    {
        _issuedAt = moment;
        return this;
    }

    /// <summary><c>exp</c> claim = <c>iat</c> + lifetime.</summary>
    public JwtBuilder Lifetime(TimeSpan lifetime)
    {
        if (lifetime <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(lifetime));
        }
        _lifetime = lifetime;
        return this;
    }

    /// <summary>Optional <c>nbf</c> claim.</summary>
    public JwtBuilder NotBefore(DateTimeOffset moment)
    {
        _notBefore = moment;
        return this;
    }

    /// <summary>
    /// Dynamic claim (private claim): accepts primitives, lists, dictionaries and
    /// nested POCOs — anything serializable with System.Text.Json.
    /// The 7 registered claims cannot be set this way: use the dedicated methods.
    /// </summary>
    public JwtBuilder Claim(string name, object? value)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        if (RegisteredClaimNames.Contains(name, StringComparer.Ordinal))
        {
            throw new JoseException(JoseFailureCode.HeaderInvalid);
        }

        _claims[name] = value;
        return this;
    }

    /// <summary>Adds dynamic claims in bulk. Same rules as <see cref="Claim"/>.</summary>
    public JwtBuilder Claims(IReadOnlyDictionary<string, object?> claims)
    {
        ArgumentNullException.ThrowIfNull(claims);
        foreach (KeyValuePair<string, object?> claim in claims)
        {
            Claim(claim.Key, claim.Value);
        }
        return this;
    }

    /// <summary>Signs with the given key (mandatory).</summary>
    public JwtBuilder SignWith(SymmetricJoseKey key, JwsAlgorithm algorithm = JwsAlgorithm.Hs256)
    {
        ArgumentNullException.ThrowIfNull(key);
        _signingKey = key;
        _signingAlgorithm = algorithm;
        return this;
    }

    /// <summary>Enables Nested JWT: the resulting JWS is encrypted as JWE with <c>cty: "JWT"</c>.</summary>
    public JwtBuilder EncryptWith(SymmetricJoseKey key, JweEncryption encryption = JweEncryption.A256Gcm)
    {
        ArgumentNullException.ThrowIfNull(key);
        _encryptionKey = key;
        _encryption = encryption;
        return this;
    }

    /// <summary>
    /// Issues the token. Without <see cref="SignWith"/> it fails: encrypting
    /// without signing is forbidden by design (a <c>dir</c> JWE without an inner
    /// signature does not authenticate the issuer when multiple parties hold the key).
    /// </summary>
    public string Create()
    {
        if (_signingKey is null)
        {
            throw new JoseException(JoseFailureCode.InvalidKey);
        }

        byte[] payload = BuildPayload();

        string jws = Jws.Sign(payload, _signingKey, new JwsSignOptions
        {
            Algorithm = _signingAlgorithm,
            Type = "JWT"
        });

        if (_encryptionKey is null)
        {
            return jws;
        }

        return Jwe.EncryptUtf8(jws, _encryptionKey, new JweEncryptOptions
        {
            Encryption = _encryption,
            Type = "JWT",
            ContentType = "JWT"
        });
    }

    private byte[] BuildPayload()
    {
        DateTimeOffset issuedAt = _issuedAt ?? DateTimeOffset.UtcNow;

        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();

            if (_issuer is not null) { writer.WriteString("iss", _issuer); }
            if (_subject is not null) { writer.WriteString("sub", _subject); }
            if (_audience is not null) { writer.WriteString("aud", _audience); }
            if (_id is not null) { writer.WriteString("jti", _id); }

            writer.WriteNumber("iat", issuedAt.ToUnixTimeSeconds());

            if (_notBefore is not null)
            {
                writer.WriteNumber("nbf", _notBefore.Value.ToUnixTimeSeconds());
            }

            if (_lifetime is not null)
            {
                writer.WriteNumber("exp", issuedAt.Add(_lifetime.Value).ToUnixTimeSeconds());
            }

            foreach (KeyValuePair<string, object?> claim in _claims)
            {
                writer.WritePropertyName(claim.Key);
                JsonSerializer.SerializeToElement(claim.Value).WriteTo(writer);
            }

            writer.WriteEndObject();
        }

        return stream.ToArray();
    }
}
