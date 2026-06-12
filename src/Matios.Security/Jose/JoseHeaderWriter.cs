using System.Text;
using System.Text.Json;

namespace Matios.Security.Jose;

/// <summary>Builds the protected header JSON when issuing JWS/JWE.</summary>
internal static class JoseHeaderWriter
{
    private static readonly string[] ReservedNames = ["alg", "enc", "zip", "crit"];

    internal static byte[] Write(string algorithm, string? encryption, string? keyId,
                                 string? type, string? contentType,
                                 IReadOnlyDictionary<string, string>? extraHeaders)
    {
        if (extraHeaders is not null)
        {
            foreach (string name in extraHeaders.Keys)
            {
                if (string.IsNullOrEmpty(name) || ReservedNames.Contains(name, StringComparer.Ordinal))
                {
                    throw new JoseException(JoseFailureCode.HeaderInvalid);
                }
            }
        }

        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("alg", algorithm);

            if (encryption is not null)
            {
                writer.WriteString("enc", encryption);
            }

            if (keyId is not null)
            {
                writer.WriteString("kid", keyId);
            }

            if (type is not null)
            {
                writer.WriteString("typ", type);
            }

            if (contentType is not null)
            {
                writer.WriteString("cty", contentType);
            }

            if (extraHeaders is not null)
            {
                foreach (KeyValuePair<string, string> header in extraHeaders)
                {
                    // typ/cty/kid via ExtraHeaders must not duplicate the dedicated options.
                    if ((header.Key == "typ" && type is not null) ||
                        (header.Key == "cty" && contentType is not null) ||
                        (header.Key == "kid" && keyId is not null))
                    {
                        throw new JoseException(JoseFailureCode.HeaderInvalid);
                    }

                    writer.WriteString(header.Key, header.Value);
                }
            }

            writer.WriteEndObject();
        }

        return stream.ToArray();
    }

    internal static byte[] AsciiBytes(string base64UrlHeader)
    {
        return Encoding.ASCII.GetBytes(base64UrlHeader);
    }
}
