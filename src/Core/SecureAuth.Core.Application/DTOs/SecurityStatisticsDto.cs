using System;

namespace SecureAuth.Core.Application.DTOs;

/// <summary>
/// DTO para estatísticas de segurança
/// </summary>
public class SecurityStatisticsDto
{
    public DateTime StartDate { get; set; }
    public DateTime EndDate { get; set; }
    public int TotalLoginAttempts { get; set; }
    public int SuccessfulLogins { get; set; }
    public int FailedLogins { get; set; }
    public int AccountLockouts { get; set; }
    public int PasswordResets { get; set; }
    public int BruteForceAttempts { get; set; }
}
