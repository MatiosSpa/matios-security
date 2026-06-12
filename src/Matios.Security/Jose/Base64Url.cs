namespace Matios.Security.Jose;

/// <summary>
/// base64url encoding (RFC 4648 §5, no padding) used across the JOSE family.
/// </summary>
internal static class Base64Url
{
    internal static string Encode(ReadOnlySpan<byte> data)
    {
        return Convert.ToBase64String(data)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    internal static byte[] Decode(string input)
    {
        if (input is null)
        {
            throw new JoseException(JoseFailureCode.MalformedToken);
        }

        foreach (char c in input)
        {
            bool valid = c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_';
            if (!valid)
            {
                throw new JoseException(JoseFailureCode.MalformedToken);
            }
        }

        int remainder = input.Length % 4;
        if (remainder == 1)
        {
            throw new JoseException(JoseFailureCode.MalformedToken);
        }

        string padded = input.Replace('-', '+').Replace('_', '/');
        padded = remainder switch
        {
            2 => padded + "==",
            3 => padded + "=",
            _ => padded
        };

        try
        {
            return Convert.FromBase64String(padded);
        }
        catch (FormatException)
        {
            throw new JoseException(JoseFailureCode.MalformedToken);
        }
    }
}
