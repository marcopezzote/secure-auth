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
/// Implementação do repositório de auditoria de segurança
/// </summary>
public class SecurityAuditRepository : ISecurityAuditRepository
{
    private readonly ApplicationDbContext _context;

    public SecurityAuditRepository(ApplicationDbContext context)
    {
        _context = context;
    }

    /// <summary>
    /// Registra um evento de segurança
    /// </summary>
    public async Task<bool> LogEventAsync(SecurityAuditLog securityLog)
    {
        _context.SecurityAuditLogs.Add(securityLog);
        var created = await _context.SaveChangesAsync();
        return created > 0;
    }

    /// <summary>
    /// Obtém logs de segurança de um usuário
    /// </summary>
    public async Task<IEnumerable<SecurityAuditLog>> GetByUserIdAsync(string userId)
    {
        return await _context.SecurityAuditLogs
            .Where(log => log.UserId == userId)
            .OrderByDescending(log => log.Timestamp)
            .ToListAsync();
    }

    /// <summary>
    /// Obtém logs de segurança dentro de um intervalo de datas
    /// </summary>
    public async Task<IEnumerable<SecurityAuditLog>> GetByDateRangeAsync(DateTime startDate, DateTime endDate)
    {
        return await _context.SecurityAuditLogs
            .Where(log => log.Timestamp >= startDate && log.Timestamp <= endDate)
            .OrderByDescending(log => log.Timestamp)
            .ToListAsync();
    }

    /// <summary>
    /// Obtém logs de segurança por tipo de evento
    /// </summary>
    public async Task<IEnumerable<SecurityAuditLog>> GetByEventTypeAsync(SecurityEventType eventType)
    {
        return await _context.SecurityAuditLogs
            .Where(log => log.EventType == eventType)
            .OrderByDescending(log => log.Timestamp)
            .ToListAsync();
    }

    /// <summary>
    /// Obtém logs de segurança por endereço IP
    /// </summary>
    public async Task<IEnumerable<SecurityAuditLog>> GetByIpAddressAsync(string ipAddress)
    {
        return await _context.SecurityAuditLogs
            .Where(log => log.IpAddress == ipAddress)
            .OrderByDescending(log => log.Timestamp)
            .ToListAsync();
    }

    /// <summary>
    /// Obtém o número de tentativas de login falhas dentro de um período
    /// </summary>
    public async Task<int> GetFailedLoginAttemptsInPeriodAsync(string userId, string ipAddress, TimeSpan period)
    {
        var startDateTime = DateTime.UtcNow.Subtract(period);
        
        var query = _context.SecurityAuditLogs
            .Where(log => log.EventType == SecurityEventType.LoginFailed)
            .Where(log => log.Timestamp >= startDateTime)
            .Where(log => !log.IsSuccess);

        // Filtrar por userId se fornecido
        if (!string.IsNullOrEmpty(userId))
        {
            query = query.Where(log => log.UserId == userId);
        }

        // Filtrar por IP se fornecido
        if (!string.IsNullOrEmpty(ipAddress))
        {
            query = query.Where(log => log.IpAddress == ipAddress);
        }

        return await query.CountAsync();
    }
}
