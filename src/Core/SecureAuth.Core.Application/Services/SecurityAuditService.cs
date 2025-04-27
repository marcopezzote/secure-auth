using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using SecureAuth.Core.Application.DTOs;
using SecureAuth.Core.Application.Interfaces;
using SecureAuth.Core.Domain.Entities;
using SecureAuth.Core.Domain.Interfaces;

namespace SecureAuth.Core.Application.Services;

/// <summary>
/// Implementação do serviço de auditoria de segurança
/// </summary>
public class SecurityAuditService : ISecurityAuditService
{
    private readonly ISecurityAuditRepository _securityAuditRepository;
    private readonly IUserRepository _userRepository;

    public SecurityAuditService(
        ISecurityAuditRepository securityAuditRepository,
        IUserRepository userRepository)
    {
        _securityAuditRepository = securityAuditRepository;
        _userRepository = userRepository;
    }

    /// <summary>
    /// Registra um evento de segurança
    /// </summary>
    public async Task<bool> LogSecurityEventAsync(SecurityEventDto securityEvent)
    {
        var securityLog = new SecurityAuditLog
        {
            Timestamp = DateTime.UtcNow,
            EventType = securityEvent.EventType,
            UserId = securityEvent.UserId,
            IpAddress = securityEvent.IpAddress,
            UserAgent = securityEvent.UserAgent,
            IsSuccess = securityEvent.IsSuccess,
            AdditionalInfo = securityEvent.AdditionalInfo
        };

        return await _securityAuditRepository.LogEventAsync(securityLog);
    }

    /// <summary>
    /// Obtém logs de segurança por usuário
    /// </summary>
    public async Task<IEnumerable<SecurityLogDto>> GetByUserIdAsync(string userId)
    {
        var logs = await _securityAuditRepository.GetByUserIdAsync(userId);
        return logs.Select(MapToDto);
    }

    /// <summary>
    /// Obtém logs de segurança dentro de um intervalo de datas
    /// </summary>
    public async Task<IEnumerable<SecurityLogDto>> GetByDateRangeAsync(DateTime startDate, DateTime endDate)
    {
        var logs = await _securityAuditRepository.GetByDateRangeAsync(startDate, endDate);
        return logs.Select(MapToDto);
    }

    /// <summary>
    /// Obtém logs de segurança por tipo de evento
    /// </summary>
    public async Task<IEnumerable<SecurityLogDto>> GetByEventTypeAsync(string eventType)
    {
        if (Enum.TryParse<SecurityEventType>(eventType, out var securityEventType))
        {
            var logs = await _securityAuditRepository.GetByEventTypeAsync(securityEventType);
            return logs.Select(MapToDto);
        }
        
        return new List<SecurityLogDto>();
    }

    /// <summary>
    /// Obtém logs de segurança por endereço IP
    /// </summary>
    public async Task<IEnumerable<SecurityLogDto>> GetByIpAddressAsync(string ipAddress)
    {
        var logs = await _securityAuditRepository.GetByIpAddressAsync(ipAddress);
        return logs.Select(MapToDto);
    }

    /// <summary>
    /// Obtém logs de falhas de login
    /// </summary>
    public async Task<IEnumerable<SecurityLogDto>> GetFailedLoginAttemptsAsync()
    {
        var logs = await _securityAuditRepository.GetByEventTypeAsync(SecurityEventType.LoginFailed);
        return logs.Select(MapToDto);
    }

    /// <summary>
    /// Obtém estatísticas de segurança
    /// </summary>
    public async Task<IEnumerable<SecurityStatisticsDto>> GetSecurityStatisticsAsync(DateTime? startDate = null, DateTime? endDate = null)
    {
        // Definir valores padrão para as datas
        if (!startDate.HasValue)
            startDate = DateTime.UtcNow.AddDays(-7);

        if (!endDate.HasValue)
            endDate = DateTime.UtcNow;

        // Obter todos os logs dentro do intervalo
        var logs = await _securityAuditRepository.GetByDateRangeAsync(startDate.Value, endDate.Value);

        // Agrupar por dia
        var groupedLogs = logs
            .GroupBy(log => log.Timestamp.Date)
            .OrderBy(g => g.Key)
            .ToList();

        var result = new List<SecurityStatisticsDto>();

        foreach (var group in groupedLogs)
        {
            var startOfDay = group.Key;
            var endOfDay = startOfDay.AddDays(1).AddTicks(-1);

            var statistics = new SecurityStatisticsDto
            {
                StartDate = startOfDay,
                EndDate = endOfDay,
                SuccessfulLogins = group.Count(log => log.EventType == SecurityEventType.Login && log.IsSuccess),
                FailedLogins = group.Count(log => log.EventType == SecurityEventType.LoginFailed),
                AccountLockouts = group.Count(log => log.EventType == SecurityEventType.AccountLocked),
                PasswordResets = group.Count(log => log.EventType == SecurityEventType.PasswordReset),
                BruteForceAttempts = group.Count(log => log.EventType == SecurityEventType.BruteForceDetected)
            };

            statistics.TotalLoginAttempts = statistics.SuccessfulLogins + statistics.FailedLogins;
            
            result.Add(statistics);
        }

        return result;
    }

    /// <summary>
    /// Verifica se há tentativa de força bruta
    /// </summary>
    public async Task<bool> CheckForBruteForceAttackAsync(string userId, string ipAddress)
    {
        const int maxAttempts = 5;
        var timeWindow = TimeSpan.FromMinutes(15);
        
        // Obter o número de tentativas falhas no período
        int failedAttempts = await _securityAuditRepository.GetFailedLoginAttemptsInPeriodAsync(
            userId, ipAddress, timeWindow);
            
        if (failedAttempts >= maxAttempts)
        {
            // Registrar evento de detecção de força bruta
            await LogSecurityEventAsync(new SecurityEventDto
            {
                EventType = SecurityEventType.BruteForceDetected,
                UserId = userId,
                IpAddress = ipAddress,
                IsSuccess = true,
                AdditionalInfo = $"Detected {failedAttempts} failed login attempts within {timeWindow.TotalMinutes} minutes"
            });
            
            // Bloquear a conta se um ID de usuário for fornecido
            if (!string.IsNullOrEmpty(userId))
            {
                var user = await _userRepository.GetByIdAsync(userId);
                if (user != null)
                {
                    // Bloquear por 15 minutos
                    user.LockoutEnd = DateTimeOffset.UtcNow.AddMinutes(15);
                    await _userRepository.UpdateAsync(user);
                }
            }
            
            return true;
        }
        
        return false;
    }

    /// <summary>
    /// Mapeia um log de auditoria para seu DTO
    /// </summary>
    private SecurityLogDto MapToDto(SecurityAuditLog log)
    {
        return new SecurityLogDto
        {
            Id = log.Id,
            Timestamp = log.Timestamp,
            EventType = log.EventType,
            UserId = log.UserId,
            UserName = log.User?.UserName,
            Email = log.User?.Email,
            IpAddress = log.IpAddress,
            UserAgent = log.UserAgent,
            IsSuccess = log.IsSuccess,
            AdditionalInfo = log.AdditionalInfo
        };
    }
}
