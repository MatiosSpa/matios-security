using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using Matios.Security.Jose;
using Xunit;

namespace Matios.Security.Tests;

public class JweNegativeTests
{
    private static SymmetricJoseKey NewKey()
    {
        return SymmetricJoseKey.FromBytes(RandomNumberGenerator.GetBytes(32));
    }

    private static string B64(string json)
    {
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(json))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private static JoseFailureCode CodeOf(Action act)
    {
        return act.Should().Throw<JoseException>().Which.FailureCode;
    }

    [Fact]
    public void Header_with_zip_is_rejected_by_design()
    {
        using SymmetricJoseKey key = NewKey();
        string header = B64("{\"alg\":\"dir\",\"enc\":\"A256GCM\",\"zip\":\"DEF\"}");
        string token = header + "..AAAAAAAAAAAAAAAA.AAAA.AAAAAAAAAAAAAAAAAAAAAA";

        CodeOf(() => Jwe.Decrypt(token, key)).Should().Be(JoseFailureCode.ZipRejected);
    }

    [Fact]
    public void Header_with_crit_is_rejected()
    {
        using SymmetricJoseKey key = NewKey();
        string header = B64("{\"alg\":\"dir\",\"enc\":\"A256GCM\",\"crit\":[\"exp\"],\"exp\":1}");
        string token = header + "..AAAAAAAAAAAAAAAA.AAAA.AAAAAAAAAAAAAAAAAAAAAA";

        CodeOf(() => Jwe.Decrypt(token, key)).Should().Be(JoseFailureCode.UnknownCritical);
    }

    [Fact]
    public void Alg_outside_whitelist_is_rejected()
    {
        using SymmetricJoseKey key = NewKey();
        string header = B64("{\"alg\":\"A256KW\",\"enc\":\"A256GCM\"}");
        string token = header + ".AAAA.AAAAAAAAAAAAAAAA.AAAA.AAAAAAAAAAAAAAAAAAAAAA";

        CodeOf(() => Jwe.Decrypt(token, key)).Should().Be(JoseFailureCode.AlgorithmNotAccepted);
    }

    [Fact]
    public void Enc_outside_whitelist_is_rejected()
    {
        using SymmetricJoseKey key = NewKey();
        string header = B64("{\"alg\":\"dir\",\"enc\":\"A128CBC-HS256\"}");
        string token = header + "..AAAAAAAAAAAAAAAA.AAAA.AAAAAAAAAAAAAAAAAAAAAA";

        CodeOf(() => Jwe.Decrypt(token, key)).Should().Be(JoseFailureCode.AlgorithmNotAccepted);
    }

    [Fact]
    public void Non_empty_encrypted_key_with_dir_is_rejected()
    {
        using SymmetricJoseKey key = NewKey();
        string valid = Jwe.EncryptUtf8("x", key);
        string[] segments = valid.Split('.');
        string tampered = string.Join('.', segments[0], "AAAA", segments[2], segments[3], segments[4]);

        CodeOf(() => Jwe.Decrypt(tampered, key)).Should().Be(JoseFailureCode.MalformedToken);
    }

    [Fact]
    public void Corrupted_tag_fails_decryption()
    {
        using SymmetricJoseKey key = NewKey();
        string valid = Jwe.EncryptUtf8("content", key);
        string[] segments = valid.Split('.');
        // Flip the FIRST tag character: the trailing one may only carry
        // base64url padding bits and decode to the same tag (flaky).
        char first = segments[4][0];
        segments[4] = (first == 'A' ? 'B' : 'A') + segments[4][1..];

        CodeOf(() => Jwe.Decrypt(string.Join('.', segments), key))
            .Should().Be(JoseFailureCode.DecryptionFailed);
    }

    [Fact]
    public void Header_tampered_after_encryption_breaks_the_aad()
    {
        using SymmetricJoseKey key = NewKey();
        string valid = Jwe.EncryptUtf8("content", key);
        string[] segments = valid.Split('.');
        // A different but structurally valid header: the AAD no longer matches the tag.
        segments[0] = B64("{\"alg\":\"dir\",\"enc\":\"A256GCM\",\"kid\":\"other\"}");

        CodeOf(() => Jwe.Decrypt(string.Join('.', segments), key))
            .Should().Be(JoseFailureCode.DecryptionFailed);
    }

    [Fact]
    public void Wrong_key_fails_decryption()
    {
        using SymmetricJoseKey issuer = NewKey();
        using SymmetricJoseKey other = NewKey();
        string token = Jwe.EncryptUtf8("secret", issuer);

        CodeOf(() => Jwe.Decrypt(token, other)).Should().Be(JoseFailureCode.DecryptionFailed);
    }

    [Fact]
    public void Four_segments_is_malformed()
    {
        using SymmetricJoseKey key = NewKey();

        CodeOf(() => Jwe.Decrypt("a.b.c.d", key)).Should().Be(JoseFailureCode.MalformedToken);
    }

    [Fact]
    public void Token_over_the_limit_is_rejected()
    {
        using SymmetricJoseKey key = NewKey();
        string token = Jwe.EncryptUtf8(new string('x', 4096), key);

        CodeOf(() => Jwe.Decrypt(token, key, new JweDecryptOptions { MaxTokenBytes = 256 }))
            .Should().Be(JoseFailureCode.TokenTooLarge);
    }

    [Fact]
    public void Key_below_256_bits_is_rejected_at_construction()
    {
        Action act = () => SymmetricJoseKey.FromBytes(RandomNumberGenerator.GetBytes(16));

        CodeOf(act).Should().Be(JoseFailureCode.InvalidKey);
    }

    [Fact]
    public void Key_of_512_bits_is_rejected_by_jwe_which_requires_exactly_256()
    {
        using SymmetricJoseKey key = SymmetricJoseKey.FromBytes(RandomNumberGenerator.GetBytes(64));

        CodeOf(() => Jwe.EncryptUtf8("x", key)).Should().Be(JoseFailureCode.InvalidKey);
    }

    [Fact]
    public void ExtraHeaders_cannot_override_alg_enc_zip_crit()
    {
        using SymmetricJoseKey key = NewKey();
        var options = new JweEncryptOptions
        {
            ExtraHeaders = new Dictionary<string, string> { ["zip"] = "DEF" }
        };

        CodeOf(() => Jwe.EncryptUtf8("x", key, options)).Should().Be(JoseFailureCode.HeaderInvalid);
    }

    [Fact]
    public void Invalid_base64url_is_malformed()
    {
        using SymmetricJoseKey key = NewKey();

        CodeOf(() => Jwe.Decrypt("not+base64url!..AAAA.AAAA.AAAA", key))
            .Should().Be(JoseFailureCode.MalformedToken);
    }

    [Fact]
    public void Jws_with_crit_is_rejected_too()
    {
        using SymmetricJoseKey key = NewKey();
        string header = B64("{\"alg\":\"HS256\",\"crit\":[\"b64\"],\"b64\":false}");
        string token = header + ".AAAA.AAAA";

        CodeOf(() => Jws.Verify(token, key)).Should().Be(JoseFailureCode.UnknownCritical);
    }

    [Fact]
    public void Jws_alg_none_never_passes()
    {
        using SymmetricJoseKey key = NewKey();
        string header = B64("{\"alg\":\"none\"}");
        string token = header + "." + B64("{\"iss\":\"attacker\"}") + ".";

        CodeOf(() => Jws.Verify(token, key)).Should().Be(JoseFailureCode.AlgorithmNotAccepted);
    }

    // ============ RFC strict corners (added 2026-06-12, public-release pass) ============

    [Fact]
    public void Duplicate_header_names_are_rejected_in_jwe()
    {
        // RFC 7515 §4 (applies to JWE headers via RFC 7516 §4): names MUST be
        // unique; this library takes the strict option and rejects duplicates.
        using SymmetricJoseKey key = NewKey();
        string header = B64("{\"alg\":\"dir\",\"enc\":\"A256GCM\",\"kid\":\"a\",\"kid\":\"b\"}");
        string token = header + "..AAAAAAAAAAAAAAAA.AAAA.AAAAAAAAAAAAAAAAAAAAAA";

        CodeOf(() => Jwe.Decrypt(token, key)).Should().Be(JoseFailureCode.HeaderInvalid);
    }

    [Fact]
    public void Duplicate_header_names_are_rejected_in_jws()
    {
        using SymmetricJoseKey key = NewKey();
        string header = B64("{\"alg\":\"HS256\",\"typ\":\"JWT\",\"typ\":\"JOSE\"}");
        string token = header + ".AAAA.AAAA";

        CodeOf(() => Jws.Verify(token, key)).Should().Be(JoseFailureCode.HeaderInvalid);
    }

    [Fact]
    public void Header_that_is_not_a_json_object_is_rejected()
    {
        using SymmetricJoseKey key = NewKey();
        string header = B64("[\"alg\",\"dir\"]");
        string token = header + "..AAAAAAAAAAAAAAAA.AAAA.AAAAAAAAAAAAAAAAAAAAAA";

        CodeOf(() => Jwe.Decrypt(token, key)).Should().Be(JoseFailureCode.HeaderInvalid);
    }

    [Fact]
    public void Header_with_utf8_bom_is_rejected_as_malformed()
    {
        using SymmetricJoseKey key = NewKey();
        byte[] bomHeader = [0xEF, 0xBB, 0xBF, .. Encoding.UTF8.GetBytes("{\"alg\":\"dir\",\"enc\":\"A256GCM\"}")];
        string header = Convert.ToBase64String(bomHeader).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        string token = header + "..AAAAAAAAAAAAAAAA.AAAA.AAAAAAAAAAAAAAAAAAAAAA";

        CodeOf(() => Jwe.Decrypt(token, key)).Should().Be(JoseFailureCode.MalformedToken);
    }

    [Fact]
    public void Header_missing_alg_is_rejected()
    {
        using SymmetricJoseKey key = NewKey();
        string header = B64("{\"enc\":\"A256GCM\"}");
        string token = header + "..AAAAAAAAAAAAAAAA.AAAA.AAAAAAAAAAAAAAAAAAAAAA";

        CodeOf(() => Jwe.Decrypt(token, key)).Should().Be(JoseFailureCode.HeaderInvalid);
    }
}
