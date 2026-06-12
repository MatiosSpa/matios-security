using System.Security.Cryptography;
using FluentAssertions;
using Matios.Security.Jose;
using Matios.Security.Jwt;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Matios.Security.Tests;

/// <summary>
/// Interop against Microsoft.IdentityModel (an independent implementation):
/// this is the JWE correctness verification for the MVP, given that RFC 7520
/// carries no official vector for dir+A256GCM (ADR-0001 D7).
/// </summary>
public class InteropMicrosoftIdentityModelTests
{
    private readonly byte[] _signingKeyBytes = RandomNumberGenerator.GetBytes(32);
    private readonly byte[] _encryptionKeyBytes = RandomNumberGenerator.GetBytes(32);

    private SymmetricJoseKey MatiosSigningKey => SymmetricJoseKey.FromBytes(_signingKeyBytes);
    private SymmetricJoseKey MatiosEncryptionKey => SymmetricJoseKey.FromBytes(_encryptionKeyBytes);

    private TokenValidationParameters MicrosoftParameters(bool withDecryption)
    {
        return new TokenValidationParameters
        {
            IssuerSigningKey = new SymmetricSecurityKey(_signingKeyBytes),
            TokenDecryptionKey = withDecryption ? new SymmetricSecurityKey(_encryptionKeyBytes) : null,
            ValidIssuer = "matios-platform",
            ValidAudience = "matios-shell",
            ValidateLifetime = true
        };
    }

    [Fact]
    public async Task Matios_issues_jws_and_microsoft_validates_it()
    {
        using SymmetricJoseKey signingKey = MatiosSigningKey;

        string token = new JwtBuilder()
            .Issuer("matios-platform")
            .Audience("matios-shell")
            .Subject("user-1")
            .Lifetime(TimeSpan.FromMinutes(10))
            .Claim("RoleId", 7L)
            .SignWith(signingKey)
            .Create();

        var handler = new JsonWebTokenHandler();
        TokenValidationResult result = await handler.ValidateTokenAsync(token, MicrosoftParameters(withDecryption: false));

        result.IsValid.Should().BeTrue(result.Exception?.ToString());
        result.Claims["sub"].Should().Be("user-1");
        Convert.ToInt64(result.Claims["RoleId"]).Should().Be(7L);
    }

    [Fact]
    public async Task Matios_issues_nested_jwe_and_microsoft_decrypts_and_validates_it()
    {
        using SymmetricJoseKey signingKey = MatiosSigningKey;
        using SymmetricJoseKey encryptionKey = MatiosEncryptionKey;

        string token = new JwtBuilder()
            .Issuer("matios-platform")
            .Audience("matios-shell")
            .Subject("user-1")
            .Lifetime(TimeSpan.FromMinutes(10))
            .Claim("RoleId", 7L)
            .SignWith(signingKey)
            .EncryptWith(encryptionKey)
            .Create();

        var handler = new JsonWebTokenHandler();
        TokenValidationResult result = await handler.ValidateTokenAsync(token, MicrosoftParameters(withDecryption: true));

        if (OperatingSystem.IsWindows())
        {
            // Windows: Microsoft.IdentityModel CAN decrypt A256GCM — this is
            // the independent-implementation conformance check for our JWE.
            result.IsValid.Should().BeTrue(result.Exception?.ToString());
            result.Claims["sub"].Should().Be("user-1");
            Convert.ToInt64(result.Claims["RoleId"]).Should().Be(7L);
        }
        else
        {
            // Linux/macOS: KNOWN Microsoft.IdentityModel limitation — its
            // crypto provider does not support A256GCM DECRYPTION on
            // non-Windows ("algorithmNotSupportedByCryptoProvider"), even
            // though the BCL AesGcm works fine there (all of this library's
            // own JWE tests pass on Linux). Canary: if a future version
            // starts supporting it, this branch fails and the full assert
            // gets unified across platforms.
            result.IsValid.Should().BeFalse();
            result.Exception.Should().NotBeNull();
        }
    }

    [Fact]
    public void Microsoft_issues_jws_and_matios_validates_it()
    {
        using SymmetricJoseKey signingKey = MatiosSigningKey;

        var handler = new JsonWebTokenHandler();
        string token = handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "matios-platform",
            Audience = "matios-shell",
            Claims = new Dictionary<string, object> { ["sub"] = "user-1", ["RoleId"] = 7L },
            Expires = DateTime.UtcNow.AddMinutes(10),
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(_signingKeyBytes), SecurityAlgorithms.HmacSha256)
        });

        JwtClaims claims = JwtValidator.Validate(token, new JwtValidationParameters
        {
            SigningKey = signingKey,
            ValidIssuer = "matios-platform",
            ValidAudience = "matios-shell"
        });

        claims.Subject.Should().Be("user-1");
        claims.GetClaim<long>("RoleId").Should().Be(7L);
    }

    [Fact]
    public void Microsoft_cannot_issue_jwe_a256gcm_documented_limitation()
    {
        // KNOWN limitation of Microsoft.IdentityModel (IDX10715): its
        // AuthenticatedEncryptionProvider DECRYPTS AES-GCM but cannot ENCRYPT
        // with it. Hence the "Microsoft issues GCM → Matios validates"
        // direction is impossible, and conformance is covered by the
        // "Matios issues → Microsoft decrypts+validates" direction above.
        // This canary pins the limitation: if a future IdentityModel version
        // starts supporting it, this test fails and the full bidirectional
        // interop gets added.
        var handler = new JsonWebTokenHandler();

        Action act = () => handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "matios-platform",
            Claims = new Dictionary<string, object> { ["sub"] = "user-1" },
            Expires = DateTime.UtcNow.AddMinutes(10),
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(_signingKeyBytes), SecurityAlgorithms.HmacSha256),
            EncryptingCredentials = new EncryptingCredentials(
                new SymmetricSecurityKey(_encryptionKeyBytes), "dir", SecurityAlgorithms.Aes256Gcm)
        });

        act.Should().Throw<SecurityTokenEncryptionFailedException>()
           .WithInnerException<NotSupportedException>();
    }
}
