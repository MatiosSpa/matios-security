namespace Matios.Security.Jose;

/// <summary>
/// The single exception of this library. The message is deliberately generic
/// and identical for every failure (anti-oracle): the detail lives in
/// <see cref="FailureCode"/> and the consumer is responsible for logging it
/// server-side without exposing it to clients.
/// </summary>
public sealed class JoseException : Exception
{
    /// <summary>Internal failure code, for consumer-side logging only.</summary>
    public JoseFailureCode FailureCode { get; }

    internal JoseException(JoseFailureCode failureCode)
        : base("JOSE operation failed.")
    {
        FailureCode = failureCode;
    }
}
