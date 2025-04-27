using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using SecureAuth.Core.Application.DTOs;
using SecureAuth.Core.Domain.Entities;

namespace SecureAuth.Core.Application.Interfaces;

/// <summary>
/// Interface para o serviço de auditoria de segurança
/// </summary>
public interface ISecurityAuditService
{
    Task<bool> LogSecurityEventAsync(SecurityEventDto securityEvent);
    Task<IEnumerable<SecurityLogDto>> GetByUserIdAsync(string userId);
    Task<IEnumerable<SecurityLogDto>> GetByDateRangeAsync(DateTime startDate, DateTime endDate);
    Task<IEnumerable<SecurityLogDto>> GetByEventTypeAsync(string eventType);
    Task<IEnumerable<SecurityLogDto>> GetByIpAddressAsync(string ipAddress);
    Task<IEnumerable<SecurityLogDto>> GetFailedLoginAttemptsAsync();
    Task<IEnumerable<SecurityStatisticsDto>> GetSecurityStatisticsAsync(DateTime? startDate = null, DateTime? endDate = null);
    Task<bool> CheckForBruteForceAttackAsync(string userId, string ipAddress);
}
