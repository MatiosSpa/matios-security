using System.Text.Json;

namespace Matios.Security.Jose;

/// <summary>Recursive conversion from <see cref="JsonElement"/> to plain CLR types.</summary>
internal static class JsonValueConverter
{
    internal static object? ToClrValue(JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.String:
                return element.GetString();

            case JsonValueKind.True:
                return true;

            case JsonValueKind.False:
                return false;

            case JsonValueKind.Number:
                if (element.TryGetInt64(out long asLong))
                {
                    return asLong;
                }
                return element.GetDouble();

            case JsonValueKind.Array:
                var list = new List<object?>(element.GetArrayLength());
                foreach (JsonElement item in element.EnumerateArray())
                {
                    list.Add(ToClrValue(item));
                }
                return list;

            case JsonValueKind.Object:
                var map = new Dictionary<string, object?>(StringComparer.Ordinal);
                foreach (JsonProperty property in element.EnumerateObject())
                {
                    map[property.Name] = ToClrValue(property.Value);
                }
                return map;

            case JsonValueKind.Null:
            default:
                return null;
        }
    }
}
