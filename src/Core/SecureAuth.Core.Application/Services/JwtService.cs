using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using SecureAuth.Core.Application.Interfaces;
using SecureAuth.Core.Application.Settings;

namespace SecureAuth.Core.Application.Services;

/// <summary>
/// Implementação do serviço JWT
/// </summary>
public class JwtService : IJwtService
{
    private readonly JwtSettings _jwtSettings;

    public JwtService(IOptions<JwtSettings> jwtSettings)
    {
        _jwtSettings = jwtSettings.Value;
    }

    /// <summary>
    /// Gera um token de acesso JWT
    /// </summary>
    public string GenerateAccessToken(string userId, string email, string[] roles)
    {
        var key = Encoding.ASCII.GetBytes(_jwtSettings.Secret);
        var tokenHandler = new JwtSecurityTokenHandler();
        
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, userId),
            new Claim(JwtRegisteredClaimNames.Email, email),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };
        
        // Adicionar papéis/funções como claims
        foreach (var role in roles)
        {
            claims.Add(new Claim("role", role));
        }

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(_jwtSettings.ExpirationInMinutes),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
            Issuer = _jwtSettings.Issuer,
            Audience = _jwtSettings.Audience
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    /// <summary>
    /// Gera um refresh token
    /// </summary>
    public string GenerateRefreshToken()
    {
        // Gerar token aleatório usando um tamanho seguro
        var randomNumber = new byte[32];
        using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }

    /// <summary>
    /// Valida um token JWT
    /// </summary>
    public bool ValidateToken(string token)
    {
        if (string.IsNullOrEmpty(token))
            return false;

        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_jwtSettings.Secret);
        
        try
        {
            tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = true,
                ValidIssuer = _jwtSettings.Issuer,
                ValidateAudience = true,
                ValidAudience = _jwtSettings.Audience,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            }, out var validatedToken);

            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Extrai informações de um token JWT
    /// </summary>
    public (string userId, string email, string[] roles) GetClaimsFromToken(string token)
    {
        if (string.IsNullOrEmpty(token))
            return (string.Empty, string.Empty, Array.Empty<string>());

        var tokenHandler = new JwtSecurityTokenHandler();
        
        try
        {
            var key = Encoding.ASCII.GetBytes(_jwtSettings.Secret);
            var principal = tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = true,
                ValidIssuer = _jwtSettings.Issuer,
                ValidateAudience = true,
                ValidAudience = _jwtSettings.Audience,
                ValidateLifetime = false // Não validar expiração aqui
            }, out var securityToken);

            var userId = principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value ?? string.Empty;
            var email = principal.FindFirst(JwtRegisteredClaimNames.Email)?.Value ?? string.Empty;
            var roles = principal.Claims
                .Where(c => c.Type == "role")
                .Select(c => c.Value)
                .ToArray();

            return (userId, email, roles);
        }
        catch
        {
            return (string.Empty, string.Empty, Array.Empty<string>());
        }
    }

    /// <summary>
    /// Obtém a data de expiração de um token
    /// </summary>
    public DateTime GetTokenExpiration(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var jwtToken = tokenHandler.ReadToken(token) as JwtSecurityToken;
        
        return jwtToken?.ValidTo ?? DateTime.MinValue;
    }
}
