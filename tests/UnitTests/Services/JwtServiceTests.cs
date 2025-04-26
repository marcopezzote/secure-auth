using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Moq;
using SecureAuth.Core.Application.Services;
using SecureAuth.Core.Application.Settings;
using Xunit;

namespace SecureAuth.UnitTests.Services;

public class JwtServiceTests
{
    private readonly JwtService _sut;
    private readonly JwtSettings _jwtSettings;

    public JwtServiceTests()
    {
        // Configurações do JWT para testes
        _jwtSettings = new JwtSettings
        {
            Secret = "ThisIsAVeryLongSecretKeyForJwtTesting12345",
            Issuer = "test-issuer",
            Audience = "test-audience",
            ExpirationInMinutes = 60
        };

        var mockOptions = new Mock<IOptions<JwtSettings>>();
        mockOptions.Setup(x => x.Value).Returns(_jwtSettings);

        _sut = new JwtService(mockOptions.Object);
    }

    [Fact]
    public void GenerateAccessToken_ReturnsValidJwtToken()
    {
        // Arrange
        var userId = "user123";
        var email = "test@example.com";
        var roles = new[] { "User", "Admin" };

        // Act
        var token = _sut.GenerateAccessToken(userId, email, roles);

        // Assert
        Assert.NotNull(token);
        Assert.NotEmpty(token);

        // Validar o token gerado
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_jwtSettings.Secret);

        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(key),
            ValidateIssuer = true,
            ValidIssuer = _jwtSettings.Issuer,
            ValidateAudience = true,
            ValidAudience = _jwtSettings.Audience,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero
        };

        var principal = tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);
        
        Assert.NotNull(principal);
        Assert.Equal(userId, principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value);
        Assert.Equal(email, principal.FindFirst(JwtRegisteredClaimNames.Email)?.Value);
        Assert.Contains(principal.Claims, c => c.Type == "role" && c.Value == "User");
        Assert.Contains(principal.Claims, c => c.Type == "role" && c.Value == "Admin");
    }

    [Fact]
    public void GenerateRefreshToken_ReturnsNonEmptyString()
    {
        // Arrange & Act
        var refreshToken = _sut.GenerateRefreshToken();

        // Assert
        Assert.NotNull(refreshToken);
        Assert.NotEmpty(refreshToken);
        Assert.True(refreshToken.Length > 16); // Deve ser uma string razoavelmente longa
    }

    [Fact]
    public void ValidateToken_WithValidToken_ReturnsTrue()
    {
        // Arrange
        var userId = "user123";
        var email = "test@example.com";
        var roles = new[] { "User" };
        var token = _sut.GenerateAccessToken(userId, email, roles);

        // Act
        var isValid = _sut.ValidateToken(token);

        // Assert
        Assert.True(isValid);
    }

    [Fact]
    public void ValidateToken_WithInvalidToken_ReturnsFalse()
    {
        // Arrange
        var invalidToken = "invalid.token.string";

        // Act
        var isValid = _sut.ValidateToken(invalidToken);

        // Assert
        Assert.False(isValid);
    }

    [Fact]
    public void ValidateToken_WithNullOrEmptyToken_ReturnsFalse()
    {
        // Act & Assert
        Assert.False(_sut.ValidateToken(null));
        Assert.False(_sut.ValidateToken(string.Empty));
    }

    [Fact]
    public void GetClaimsFromToken_WithValidToken_ReturnsClaims()
    {
        // Arrange
        var userId = "user123";
        var email = "test@example.com";
        var roles = new[] { "User", "Admin" };
        var token = _sut.GenerateAccessToken(userId, email, roles);

        // Act
        var (extractedUserId, extractedEmail, extractedRoles) = _sut.GetClaimsFromToken(token);

        // Assert
        Assert.Equal(userId, extractedUserId);
        Assert.Equal(email, extractedEmail);
        Assert.Equal(roles.Length, extractedRoles.Length);
        Assert.Contains("User", extractedRoles);
        Assert.Contains("Admin", extractedRoles);
    }

    [Fact]
    public void GetClaimsFromToken_WithInvalidToken_ReturnsNullValues()
    {
        // Arrange
        var invalidToken = "invalid.token.string";

        // Act
        var (userId, email, roles) = _sut.GetClaimsFromToken(invalidToken);

        // Assert
        Assert.Null(userId);
        Assert.Null(email);
        Assert.Empty(roles);
    }

    [Fact]
    public void GetTokenExpiration_ReturnsCorrectExpiration()
    {
        // Arrange
        var userId = "user123";
        var email = "test@example.com";
        var roles = new[] { "User" };
        var token = _sut.GenerateAccessToken(userId, email, roles);

        // Act
        var expiration = _sut.GetTokenExpiration(token);

        // Assert
        // A expiração deve estar próxima do tempo atual + o tempo de expiração configurado
        var expectedExpiration = DateTime.UtcNow.AddMinutes(_jwtSettings.ExpirationInMinutes);
        
        // Permitir uma pequena diferença devido ao tempo de execução do teste
        var difference = expectedExpiration - expiration;
        Assert.True(difference.TotalSeconds < 10); // diferença menor que 10 segundos
    }
}
