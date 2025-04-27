using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using SecureAuth.Core.Domain.Entities;

namespace SecureAuth.Core.Domain.Interfaces;

/// <summary>
/// Interface para repositório de auditoria de segurança
/// </summary>
public interface ISecurityAuditRepository
{
    Task<bool> LogEventAsync(SecurityAuditLog securityLog);
    Task<IEnumerable<SecurityAuditLog>> GetByUserIdAsync(string userId);
    Task<IEnumerable<SecurityAuditLog>> GetByDateRangeAsync(DateTime startDate, DateTime endDate);
    Task<IEnumerable<SecurityAuditLog>> GetByEventTypeAsync(SecurityEventType eventType);
    Task<IEnumerable<SecurityAuditLog>> GetByIpAddressAsync(string ipAddress);
    Task<int> GetFailedLoginAttemptsInPeriodAsync(string userId, string ipAddress, TimeSpan period);
}
