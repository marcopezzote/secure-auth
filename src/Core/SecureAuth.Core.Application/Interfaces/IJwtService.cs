using System;
using System.Threading.Tasks;

namespace SecureAuth.Core.Application.Interfaces
{
    /// <summary>
    /// Interface para o serviço JWT
    /// </summary>
    public interface IJwtService
    {
        string GenerateAccessToken(string userId, string email, string[] roles);
        string GenerateRefreshToken();
        bool ValidateToken(string token);
        (string userId, string email, string[] roles) GetClaimsFromToken(string token);
        DateTime GetTokenExpiration(string token);
    }
}
