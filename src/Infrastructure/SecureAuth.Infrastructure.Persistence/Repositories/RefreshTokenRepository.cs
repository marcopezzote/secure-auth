using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using SecureAuth.Infrastructure.Persistence.Contexts;
using SecureAuth.Infrastructure.Persistence.Interfaces;
using SecureAuth.Infrastructure.Persistence.Models;

namespace SecureAuth.Infrastructure.Persistence.Repositories;

/// <summary>
/// Implementação do repositório de refresh tokens
/// </summary>
public class RefreshTokenRepository : IRefreshTokenRepository
{
    private readonly ApplicationDbContext _context;

    public RefreshTokenRepository(ApplicationDbContext context)
    {
        _context = context;
    }

    /// <summary>
    /// Obtém um token pelo valor
    /// </summary>
    public async Task<RefreshToken> GetByTokenAsync(string token)
    {
        return await _context.RefreshTokens
            .FirstOrDefaultAsync(t => t.Token == token)
            ?? new RefreshToken();
    }

    /// <summary>
    /// Obtém todos os tokens de um usuário
    /// </summary>
    public async Task<IEnumerable<RefreshToken>> GetByUserIdAsync(string userId)
    {
        return await _context.RefreshTokens
            .Where(t => t.UserId == userId)
            .OrderByDescending(t => t.Created)
            .ToListAsync();
    }

    /// <summary>
    /// Cria um novo refresh token
    /// </summary>
    public async Task<bool> CreateAsync(RefreshToken refreshToken)
    {
        _context.RefreshTokens.Add(refreshToken);
        var created = await _context.SaveChangesAsync();
        return created > 0;
    }

    /// <summary>
    /// Atualiza um refresh token existente
    /// </summary>
    public async Task<bool> UpdateAsync(RefreshToken refreshToken)
    {
        _context.RefreshTokens.Update(refreshToken);
        var updated = await _context.SaveChangesAsync();
        return updated > 0;
    }

    /// <summary>
    /// Exclui um refresh token
    /// </summary>
    public async Task<bool> DeleteAsync(int id)
    {
        var token = await _context.RefreshTokens.FindAsync(id);
        if (token == null)
        {
            return false;
        }

        _context.RefreshTokens.Remove(token);
        var deleted = await _context.SaveChangesAsync();
        return deleted > 0;
    }

    /// <summary>
    /// Revoga todos os tokens de um usuário
    /// </summary>
    public async Task<bool> RevokeAllUserTokensAsync(string userId, string ipAddress, string reason)
    {
        var tokens = await _context.RefreshTokens
            .Where(t => t.UserId == userId && t.IsActive)
            .ToListAsync();

        if (!tokens.Any())
        {
            return true;
        }

        foreach (var token in tokens)
        {
            token.Revoked = DateTime.UtcNow;
            token.RevokedByIp = ipAddress;
            token.ReasonRevoked = reason;
        }

        _context.UpdateRange(tokens);
        var updated = await _context.SaveChangesAsync();
        return updated > 0;
    }

    /// <summary>
    /// Verifica se um token está ativo
    /// </summary>
    public async Task<bool> IsTokenActiveAsync(string token)
    {
        var refreshToken = await GetByTokenAsync(token);
        return refreshToken != null && refreshToken.IsActive;
    }
}
