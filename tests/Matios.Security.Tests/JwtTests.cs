using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using Matios.Security.Jose;
using Matios.Security.Jwt;
using Xunit;

namespace Matios.Security.Tests;

public class JwtTests
{
    private readonly SymmetricJoseKey _signingKey =
        SymmetricJoseKey.FromBytes(RandomNumberGenerator.GetBytes(32), "sig-2026");

    private readonly SymmetricJoseKey _encryptionKey =
        SymmetricJoseKey.FromBytes(RandomNumberGenerator.GetBytes(32), "enc-2026");

    private sealed record SampleContext(string Tenant, int Level);

    private JwtBuilder BaseBuilder()
    {
        return new JwtBuilder()
            .Issuer("matios-platform")
            .Audience("matios-shell")
            .Subject("user-uid-1")
            .IdAuto()
            .Lifetime(TimeSpan.FromMinutes(30))
            .SignWith(_signingKey);
    }

    private JwtValidationParameters BaseParameters(bool withDecryption = false)
    {
        return new JwtValidationParameters
        {
            SigningKey = _signingKey,
            DecryptionKey = withDecryption ? _encryptionKey : null,
            ValidIssuer = "matios-platform",
            ValidAudience = "matios-shell"
        };
    }

    [Fact]
    public void Plain_jws_roundtrip_with_dynamic_claims()
    {
        string token = BaseBuilder()
            .Claim("RoleId", 7L)
            .Claim("companyIds", new List<long> { 1, 4, 9 })
            .Claim("permCipher", "dHJ1ZTtmYWxzZTt0cnVl")
            .Claim("context", new SampleContext("duoc", 3))
            .Create();

        token.Split('.').Should().HaveCount(3);

        JwtClaims claims = JwtValidator.Validate(token, BaseParameters());

        claims.Subject.Should().Be("user-uid-1");
        claims.GetClaim<long>("RoleId").Should().Be(7L);
        claims.GetClaim<List<long>>("companyIds").Should().Equal(1, 4, 9);
        claims.GetClaim<string>("permCipher").Should().Be("dHJ1ZTtmYWxzZTt0cnVl");
        claims.GetClaim<SampleContext>("context").Should().Be(new SampleContext("duoc", 3));
        claims.OuterHeader.Should().BeNull();
    }

    [Fact]
    public void Nested_jwt_roundtrip_encrypted_and_signed()
    {
        string token = BaseBuilder()
            .Claim("RoleId", 7L)
            .EncryptWith(_encryptionKey)
            .Create();

        token.Split('.').Should().HaveCount(5);

        JwtClaims claims = JwtValidator.Validate(token, BaseParameters(withDecryption: true));

        claims.GetClaim<long>("RoleId").Should().Be(7L);
        claims.Header.Algorithm.Should().Be("HS256");
        claims.OuterHeader.Should().NotBeNull();
        claims.OuterHeader!.Algorithm.Should().Be("dir");
        claims.OuterHeader.ContentType.Should().Be("JWT");
    }

    [Fact]
    public void Nested_jwt_does_not_expose_claims_in_clear()
    {
        string token = BaseBuilder()
            .Claim("businessSecret", "must-not-be-visible")
            .EncryptWith(_encryptionKey)
            .Create();

        token.Should().NotContain("businessSecret");
        // In a plain JWS the payload is readable base64url; here it must be opaque.
    }

    [Fact]
    public void Downgrade_to_plain_jws_is_rejected_when_jwe_is_expected()
    {
        string plainJws = BaseBuilder().Create();

        Action act = () => JwtValidator.Validate(plainJws, BaseParameters(withDecryption: true));

        act.Should().Throw<JoseException>()
           .Which.FailureCode.Should().Be(JoseFailureCode.AlgorithmNotAccepted);
    }

    [Fact]
    public void Jwe_token_without_decryption_key_is_rejected()
    {
        string nested = BaseBuilder().EncryptWith(_encryptionKey).Create();

        Action act = () => JwtValidator.Validate(nested, BaseParameters());

        act.Should().Throw<JoseException>()
           .Which.FailureCode.Should().Be(JoseFailureCode.MalformedToken);
    }

    [Fact]
    public void Expired_token_is_rejected()
    {
        string token = new JwtBuilder()
            .Subject("user")
            .IssuedAt(DateTimeOffset.UtcNow.AddHours(-2))
            .Lifetime(TimeSpan.FromMinutes(5))
            .SignWith(_signingKey)
            .Create();

        Action act = () => JwtValidator.Validate(token, new JwtValidationParameters { SigningKey = _signingKey });

        act.Should().Throw<JoseException>()
           .Which.FailureCode.Should().Be(JoseFailureCode.TokenExpired);
    }

    [Fact]
    public void Clock_skew_tolerates_recent_expiration()
    {
        string token = new JwtBuilder()
            .Subject("user")
            .IssuedAt(DateTimeOffset.UtcNow.AddMinutes(-5).AddSeconds(-30))
            .Lifetime(TimeSpan.FromMinutes(5))   // expired ~30s ago
            .SignWith(_signingKey)
            .Create();

        var parameters = new JwtValidationParameters
        {
            SigningKey = _signingKey,
            ClockSkew = TimeSpan.FromSeconds(60)
        };

        JwtValidator.Validate(token, parameters).Subject.Should().Be("user");
    }

    [Fact]
    public void Missing_exp_is_rejected_by_default_and_passes_with_optout()
    {
        string token = new JwtBuilder().Subject("user").SignWith(_signingKey).Create();

        Action strict = () => JwtValidator.Validate(token, new JwtValidationParameters { SigningKey = _signingKey });
        strict.Should().Throw<JoseException>()
              .Which.FailureCode.Should().Be(JoseFailureCode.MissingClaim);

        var relaxed = new JwtValidationParameters { SigningKey = _signingKey, RequireExpiration = false };
        JwtValidator.Validate(token, relaxed).Subject.Should().Be("user");
    }

    [Fact]
    public void Future_nbf_is_rejected()
    {
        string token = BaseBuilder()
            .NotBefore(DateTimeOffset.UtcNow.AddMinutes(10))
            .Create();

        Action act = () => JwtValidator.Validate(token, BaseParameters());

        act.Should().Throw<JoseException>()
           .Which.FailureCode.Should().Be(JoseFailureCode.TokenNotYetValid);
    }

    [Theory]
    [InlineData("other-issuer", "matios-shell", JoseFailureCode.IssuerMismatch)]
    [InlineData("matios-platform", "other-audience", JoseFailureCode.AudienceMismatch)]
    public void Wrong_issuer_or_audience_is_rejected(string validIssuer, string validAudience,
                                                     JoseFailureCode expected)
    {
        string token = BaseBuilder().Create();

        var parameters = new JwtValidationParameters
        {
            SigningKey = _signingKey,
            ValidIssuer = validIssuer,
            ValidAudience = validAudience
        };

        Action act = () => JwtValidator.Validate(token, parameters);

        act.Should().Throw<JoseException>().Which.FailureCode.Should().Be(expected);
    }

    [Fact]
    public void Registered_claims_cannot_be_set_through_dynamic_claim()
    {
        Action act = () => new JwtBuilder().Claim("iss", "attacker");

        act.Should().Throw<JoseException>()
           .Which.FailureCode.Should().Be(JoseFailureCode.HeaderInvalid);
    }

    [Fact]
    public void Encrypting_without_signing_is_forbidden()
    {
        Action act = () => new JwtBuilder()
            .Subject("user")
            .EncryptWith(_encryptionKey)
            .Create();

        act.Should().Throw<JoseException>()
           .Which.FailureCode.Should().Be(JoseFailureCode.InvalidKey);
    }

    [Fact]
    public void TryValidate_returns_false_and_code_without_throwing()
    {
        string token = BaseBuilder().Create();
        string tampered = token[..^2] + "AA";

        bool ok = JwtValidator.TryValidate(tampered, BaseParameters(),
                                           out JwtClaims? claims, out JoseFailureCode? failure);

        ok.Should().BeFalse();
        claims.Should().BeNull();
        failure.Should().Be(JoseFailureCode.SignatureInvalid);
    }

    [Fact]
    public void TryGetClaim_distinguishes_absent_from_present()
    {
        string token = BaseBuilder().Claim("RoleId", 7L).Create();
        JwtClaims claims = JwtValidator.Validate(token, BaseParameters());

        claims.TryGetClaim("RoleId", out long roleId).Should().BeTrue();
        roleId.Should().Be(7L);
        claims.TryGetClaim("doesNotExist", out long _).Should().BeFalse();
    }

    [Fact]
    public void GetClaim_with_incompatible_type_throws_claim_type_mismatch()
    {
        string token = BaseBuilder().Claim("RoleId", "not-a-number").Create();
        JwtClaims claims = JwtValidator.Validate(token, BaseParameters());

        Action act = () => claims.GetClaim<long>("RoleId");

        act.Should().Throw<JoseException>()
           .Which.FailureCode.Should().Be(JoseFailureCode.ClaimTypeMismatch);
    }

    // ============ RFC strict corner (added 2026-06-12, public-release pass) ============

    [Fact]
    public void Duplicate_claim_names_are_rejected()
    {
        // RFC 7519 §4: claim names MUST be unique. Forge a JWS whose payload
        // carries a duplicated claim and check the strict rejection.
        byte[] payload = Encoding.UTF8.GetBytes(
            "{\"sub\":\"user\",\"exp\":" +
            DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds() +
            ",\"RoleId\":1,\"RoleId\":2}");
        string token = Jws.Sign(payload, _signingKey, new JwsSignOptions { Type = "JWT" });

        Action act = () => JwtValidator.Validate(token, new JwtValidationParameters { SigningKey = _signingKey });

        act.Should().Throw<JoseException>()
           .Which.FailureCode.Should().Be(JoseFailureCode.MalformedToken);
    }
}
