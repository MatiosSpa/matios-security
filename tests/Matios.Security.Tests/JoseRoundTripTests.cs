using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using Matios.Security.Jose;
using Xunit;

namespace Matios.Security.Tests;

public class JoseRoundTripTests
{
    private static SymmetricJoseKey NewKey(string? kid = null)
    {
        return SymmetricJoseKey.FromBytes(RandomNumberGenerator.GetBytes(32), kid);
    }

    // ============ JWS — official vector RFC 7515 Appendix A.1 (HS256) ============
    // Coverage note (ADR-0001 D7): RFC 7520 has NO vector for dir+A256GCM
    // (its §5.6 uses A128GCM, outside the MVP scope). The independent
    // verification of the JWE is the bidirectional interop against
    // Microsoft.IdentityModel.

    private const string Rfc7515A1Key =
        "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";

    private const string Rfc7515A1Token =
        "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
        ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
        ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    [Fact]
    public void Verify_accepts_official_rfc7515_a1_vector()
    {
        using SymmetricJoseKey key = SymmetricJoseKey.FromBase64Url(Rfc7515A1Key);

        JwsVerifyResult result = Jws.Verify(Rfc7515A1Token, key);

        result.PayloadUtf8.Should().Contain("\"iss\":\"joe\"");
        result.Header.Algorithm.Should().Be("HS256");
        result.Header.Type.Should().Be("JWT");
    }

    [Fact]
    public void Verify_rejects_rfc7515_a1_vector_with_tampered_signature()
    {
        using SymmetricJoseKey key = SymmetricJoseKey.FromBase64Url(Rfc7515A1Key);
        string tampered = Rfc7515A1Token[..^2] + "AA";

        Action act = () => Jws.Verify(tampered, key);

        act.Should().Throw<JoseException>()
           .Which.FailureCode.Should().Be(JoseFailureCode.SignatureInvalid);
    }

    // ============ Round-trips ============

    [Fact]
    public void Jws_sign_verify_roundtrip()
    {
        using SymmetricJoseKey key = NewKey("sig-1");
        byte[] payload = Encoding.UTF8.GetBytes("{\"hello\":\"world\"}");

        string token = Jws.Sign(payload, key, new JwsSignOptions { Type = "JWT" });
        JwsVerifyResult result = Jws.Verify(token, key);

        result.Payload.Should().Equal(payload);
        result.Header.KeyId.Should().Be("sig-1");
        result.Header.Type.Should().Be("JWT");
    }

    [Fact]
    public void Jwe_encrypt_decrypt_roundtrip_bytes()
    {
        using SymmetricJoseKey key = NewKey("enc-1");
        byte[] plaintext = RandomNumberGenerator.GetBytes(1024);

        string token = Jwe.Encrypt(plaintext, key);
        JweDecryptResult result = Jwe.Decrypt(token, key);

        result.Plaintext.Should().Equal(plaintext);
        result.Header.Algorithm.Should().Be("dir");
        result.Header.Encryption.Should().Be("A256GCM");
        result.Header.KeyId.Should().Be("enc-1");
    }

    [Fact]
    public void Jwe_encrypt_decrypt_roundtrip_utf8_with_accents()
    {
        using SymmetricJoseKey key = NewKey();
        const string plaintext = "Contenido cifrado en español: año, corazón, ñandú.";

        string token = Jwe.EncryptUtf8(plaintext, key);

        Jwe.Decrypt(token, key).PlaintextUtf8.Should().Be(plaintext);
    }

    [Fact]
    public void Jwe_compact_has_5_segments_and_empty_encrypted_key_for_dir()
    {
        using SymmetricJoseKey key = NewKey();

        string token = Jwe.EncryptUtf8("x", key);
        string[] segments = token.Split('.');

        segments.Should().HaveCount(5);
        segments[1].Should().BeEmpty();   // RFC 7518 §4.5
    }

    [Fact]
    public void Jwe_produces_distinct_tokens_for_same_plaintext_due_to_random_iv()
    {
        using SymmetricJoseKey key = NewKey();

        Jwe.EncryptUtf8("same thing", key).Should().NotBe(Jwe.EncryptUtf8("same thing", key));
    }
}
