using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using SecureAuth.Infrastructure.Persistence.Models;

namespace SecureAuth.Infrastructure.Persistence.Interfaces
{
    /// <summary>
    /// Interface para repositório de refresh tokens
    /// </summary>
    public interface IRefreshTokenRepository
    {
        Task<RefreshToken> GetByTokenAsync(string token);
        Task<IEnumerable<RefreshToken>> GetByUserIdAsync(string userId);
        Task<bool> CreateAsync(RefreshToken refreshToken);
        Task<bool> UpdateAsync(RefreshToken refreshToken);
        Task<bool> DeleteAsync(int id);
        Task<bool> RevokeAllUserTokensAsync(string userId, string ipAddress, string reason);
        Task<bool> IsTokenActiveAsync(string token);
    }
}
