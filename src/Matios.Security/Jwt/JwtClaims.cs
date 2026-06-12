using System.Text.Json;
using Matios.Security.Jose;

namespace Matios.Security.Jwt;

/// <summary>
/// Claims of an already-validated JWT. Typed reads of dynamic claims via
/// <see cref="GetClaim{T}"/> / <see cref="TryGetClaim{T}"/> (System.Text.Json).
/// </summary>
public sealed class JwtClaims
{
    private readonly JsonElement _payload;
    private IReadOnlyDictionary<string, object?>? _all;

    /// <summary><c>iss</c> claim.</summary>
    public string? Issuer { get; }

    /// <summary><c>sub</c> claim.</summary>
    public string? Subject { get; }

    /// <summary><c>aud</c> claim (first audience when it came as an array).</summary>
    public string? Audience { get; }

    /// <summary><c>jti</c> claim.</summary>
    public string? Id { get; }

    /// <summary><c>exp</c> claim.</summary>
    public DateTimeOffset? ExpiresAt { get; }

    /// <summary><c>iat</c> claim.</summary>
    public DateTimeOffset? IssuedAt { get; }

    /// <summary><c>nbf</c> claim.</summary>
    public DateTimeOffset? NotBefore { get; }

    /// <summary>Header of the inner JWS.</summary>
    public JoseHeader Header { get; }

    /// <summary>Header of the outer JWE when the token was a Nested JWT; null for plain JWS.</summary>
    public JoseHeader? OuterHeader { get; }

    internal JwtClaims(JsonElement payload, JoseHeader header, JoseHeader? outerHeader)
    {
        _payload = payload;
        Header = header;
        OuterHeader = outerHeader;

        Issuer = ReadString("iss");
        Subject = ReadString("sub");
        Audience = ReadAudience();
        Id = ReadString("jti");
        ExpiresAt = ReadUnixSeconds("exp");
        IssuedAt = ReadUnixSeconds("iat");
        NotBefore = ReadUnixSeconds("nbf");
    }

    /// <summary>
    /// Reads a dynamic claim deserializing it to the requested type. Absent claim →
    /// default; incompatible type → <see cref="JoseException"/> with
    /// <see cref="JoseFailureCode.ClaimTypeMismatch"/>.
    /// </summary>
    public T? GetClaim<T>(string name)
    {
        TryGetClaim(name, out T? value);
        return value;
    }

    /// <summary>Variant that distinguishes "absent claim" (false) from "present claim" (true).</summary>
    public bool TryGetClaim<T>(string name, out T? value)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);

        if (!_payload.TryGetProperty(name, out JsonElement element))
        {
            value = default;
            return false;
        }

        try
        {
            value = element.Deserialize<T>();
            return true;
        }
        catch (JsonException)
        {
            throw new JoseException(JoseFailureCode.ClaimTypeMismatch);
        }
        catch (InvalidOperationException)
        {
            throw new JoseException(JoseFailureCode.ClaimTypeMismatch);
        }
    }

    /// <summary>All claims as a read-only dictionary (plain CLR conversion).</summary>
    public IReadOnlyDictionary<string, object?> All
    {
        get
        {
            if (_all is null)
            {
                var map = new Dictionary<string, object?>(StringComparer.Ordinal);
                foreach (JsonProperty property in _payload.EnumerateObject())
                {
                    map[property.Name] = JsonValueConverter.ToClrValue(property.Value);
                }
                _all = map;
            }
            return _all;
        }
    }

    internal JsonElement Payload => _payload;

    private string? ReadString(string name)
    {
        if (_payload.TryGetProperty(name, out JsonElement element) &&
            element.ValueKind == JsonValueKind.String)
        {
            return element.GetString();
        }
        return null;
    }

    private string? ReadAudience()
    {
        if (!_payload.TryGetProperty("aud", out JsonElement element))
        {
            return null;
        }

        if (element.ValueKind == JsonValueKind.String)
        {
            return element.GetString();
        }

        if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement item in element.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.String)
                {
                    return item.GetString();
                }
            }
        }

        return null;
    }

    private DateTimeOffset? ReadUnixSeconds(string name)
    {
        if (_payload.TryGetProperty(name, out JsonElement element) &&
            element.ValueKind == JsonValueKind.Number &&
            element.TryGetInt64(out long seconds))
        {
            return DateTimeOffset.FromUnixTimeSeconds(seconds);
        }
        return null;
    }
}
