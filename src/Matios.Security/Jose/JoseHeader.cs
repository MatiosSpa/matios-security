using System.Text.Json;

namespace Matios.Security.Jose;

/// <summary>
/// JOSE protected header, parsed and structurally validated.
/// Read-only; the complete raw values are in <see cref="All"/>.
/// </summary>
public sealed class JoseHeader
{
    /// <summary>Raw value of the <c>alg</c> parameter.</summary>
    public string Algorithm { get; }

    /// <summary>Raw value of the <c>enc</c> parameter (JWE only; null in JWS).</summary>
    public string? Encryption { get; }

    /// <summary>Value of the <c>kid</c> parameter, if present.</summary>
    public string? KeyId { get; }

    /// <summary>Value of the <c>typ</c> parameter, if present.</summary>
    public string? Type { get; }

    /// <summary>Value of the <c>cty</c> parameter, if present.</summary>
    public string? ContentType { get; }

    /// <summary>All header parameters as a read-only dictionary.</summary>
    public IReadOnlyDictionary<string, object?> All { get; }

    private JoseHeader(string algorithm, string? encryption, string? keyId, string? type,
                       string? contentType, IReadOnlyDictionary<string, object?> all)
    {
        Algorithm = algorithm;
        Encryption = encryption;
        KeyId = keyId;
        Type = type;
        ContentType = contentType;
        All = all;
    }

    /// <summary>
    /// Parses and structurally validates a protected header. Locked rules:
    /// <c>zip</c> present → reject; <c>crit</c> present → reject (the library
    /// supports no critical parameters); <c>alg</c> missing or non-string →
    /// reject; duplicate parameter names → reject (RFC 7515 §4, strict option).
    /// </summary>
    internal static JoseHeader Parse(byte[] headerJsonUtf8)
    {
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(headerJsonUtf8);
        }
        catch (JsonException)
        {
            throw new JoseException(JoseFailureCode.MalformedToken);
        }

        using (document)
        {
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                throw new JoseException(JoseFailureCode.HeaderInvalid);
            }

            if (root.TryGetProperty("zip", out _))
            {
                throw new JoseException(JoseFailureCode.ZipRejected);
            }

            if (root.TryGetProperty("crit", out _))
            {
                throw new JoseException(JoseFailureCode.UnknownCritical);
            }

            string? algorithm = ReadOptionalString(root, "alg");
            if (string.IsNullOrEmpty(algorithm))
            {
                throw new JoseException(JoseFailureCode.HeaderInvalid);
            }

            // RFC 7515 §4: header parameter names MUST be unique; this
            // implementation takes the strict option and rejects duplicates.
            var all = new Dictionary<string, object?>(StringComparer.Ordinal);
            foreach (JsonProperty property in root.EnumerateObject())
            {
                if (!all.TryAdd(property.Name, JsonValueConverter.ToClrValue(property.Value)))
                {
                    throw new JoseException(JoseFailureCode.HeaderInvalid);
                }
            }

            return new JoseHeader(
                algorithm,
                ReadOptionalString(root, "enc"),
                ReadOptionalString(root, "kid"),
                ReadOptionalString(root, "typ"),
                ReadOptionalString(root, "cty"),
                all);
        }
    }

    private static string? ReadOptionalString(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out JsonElement value))
        {
            return null;
        }

        if (value.ValueKind != JsonValueKind.String)
        {
            throw new JoseException(JoseFailureCode.HeaderInvalid);
        }

        return value.GetString();
    }
}
