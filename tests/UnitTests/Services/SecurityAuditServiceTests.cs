using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Moq;
using SecureAuth.Core.Application.DTOs;
using SecureAuth.Core.Application.Services;
using SecureAuth.Core.Domain.Entities;
using SecureAuth.Core.Domain.Interfaces;
using Xunit;

namespace SecureAuth.UnitTests.Services;

public class SecurityAuditServiceTests
{
    private readonly Mock<ISecurityAuditRepository> _mockSecurityAuditRepository;
    private readonly Mock<IUserRepository> _mockUserRepository;
    private readonly SecurityAuditService _sut;

    public SecurityAuditServiceTests()
    {
        _mockSecurityAuditRepository = new Mock<ISecurityAuditRepository>();
        _mockUserRepository = new Mock<IUserRepository>();
        _sut = new SecurityAuditService(_mockSecurityAuditRepository.Object, _mockUserRepository.Object);
    }

    [Fact]
    public async Task LogSecurityEvent_ShouldLogEventSuccessfully()
    {
        // Arrange
        var securityEvent = new SecurityEventDto
        {
            EventType = SecurityEventType.Login,
            UserId = "user123",
            IpAddress = "127.0.0.1",
            UserAgent = "Test Agent",
            IsSuccess = true,
            AdditionalInfo = "Test login"
        };

        _mockSecurityAuditRepository
            .Setup(x => x.LogEventAsync(It.IsAny<SecurityAuditLog>()))
            .ReturnsAsync(true);

        // Act
        var result = await _sut.LogSecurityEventAsync(securityEvent);

        // Assert
        Assert.True(result);
        _mockSecurityAuditRepository.Verify(
            x => x.LogEventAsync(It.Is<SecurityAuditLog>(log =>
                log.EventType == securityEvent.EventType &&
                log.UserId == securityEvent.UserId &&
                log.IpAddress == securityEvent.IpAddress &&
                log.UserAgent == securityEvent.UserAgent &&
                log.IsSuccess == securityEvent.IsSuccess &&
                log.AdditionalInfo == securityEvent.AdditionalInfo
            )),
            Times.Once
        );
    }

    [Fact]
    public async Task GetByUserId_ShouldReturnUserLogs()
    {
        // Arrange
        var userId = "user123";
        var logs = new List<SecurityAuditLog>
        {
            new SecurityAuditLog
            {
                Id = 1,
                UserId = userId,
                EventType = SecurityEventType.Login,
                IpAddress = "127.0.0.1",
                Timestamp = DateTime.UtcNow,
                IsSuccess = true
            },
            new SecurityAuditLog
            {
                Id = 2,
                UserId = userId,
                EventType = SecurityEventType.PasswordReset,
                IpAddress = "127.0.0.1",
                Timestamp = DateTime.UtcNow.AddMinutes(-10),
                IsSuccess = true
            }
        };

        _mockSecurityAuditRepository
            .Setup(x => x.GetByUserIdAsync(userId))
            .ReturnsAsync(logs);

        // Act
        var result = await _sut.GetByUserIdAsync(userId);

        // Assert
        var resultList = result.ToList();
        Assert.Equal(2, resultList.Count);
        Assert.Equal(logs[0].Id, resultList[0].Id);
        Assert.Equal(logs[0].EventType, resultList[0].EventType);
        Assert.Equal(logs[1].Id, resultList[1].Id);
        Assert.Equal(logs[1].EventType, resultList[1].EventType);
    }

    [Fact]
    public async Task GetByDateRange_ShouldReturnLogsWithinRange()
    {
        // Arrange
        var startDate = DateTime.UtcNow.AddDays(-1);
        var endDate = DateTime.UtcNow;
        
        var logs = new List<SecurityAuditLog>
        {
            new SecurityAuditLog
            {
                Id = 1,
                UserId = "user1",
                EventType = SecurityEventType.Login,
                Timestamp = startDate.AddHours(1),
                IsSuccess = true
            },
            new SecurityAuditLog
            {
                Id = 2,
                UserId = "user2",
                EventType = SecurityEventType.LoginFailed,
                Timestamp = startDate.AddHours(12),
                IsSuccess = false
            }
        };

        _mockSecurityAuditRepository
            .Setup(x => x.GetByDateRangeAsync(startDate, endDate))
            .ReturnsAsync(logs);

        // Act
        var result = await _sut.GetByDateRangeAsync(startDate, endDate);

        // Assert
        var resultList = result.ToList();
        Assert.Equal(2, resultList.Count);
        Assert.Equal(logs[0].Id, resultList[0].Id);
        Assert.Equal(logs[1].Id, resultList[1].Id);
    }

    [Fact]
    public async Task GetSecurityStatistics_ShouldReturnCorrectStatistics()
    {
        // Arrange
        var startDate = DateTime.UtcNow.AddDays(-7);
        var endDate = DateTime.UtcNow;
        
        // Criar logs de teste com diferentes tipos de eventos em diferentes datas
        var logs = new List<SecurityAuditLog>();
        
        // Dia 1: 2 logins bem-sucedidos, 1 falha de login
        var day1 = DateTime.UtcNow.AddDays(-6).Date;
        logs.Add(new SecurityAuditLog { EventType = SecurityEventType.Login, Timestamp = day1.AddHours(1), IsSuccess = true });
        logs.Add(new SecurityAuditLog { EventType = SecurityEventType.Login, Timestamp = day1.AddHours(2), IsSuccess = true });
        logs.Add(new SecurityAuditLog { EventType = SecurityEventType.LoginFailed, Timestamp = day1.AddHours(3), IsSuccess = false });
        
        // Dia 2: 1 login bem-sucedido, 2 falhas de login, 1 bloqueio de conta
        var day2 = DateTime.UtcNow.AddDays(-5).Date;
        logs.Add(new SecurityAuditLog { EventType = SecurityEventType.Login, Timestamp = day2.AddHours(1), IsSuccess = true });
        logs.Add(new SecurityAuditLog { EventType = SecurityEventType.LoginFailed, Timestamp = day2.AddHours(2), IsSuccess = false });
        logs.Add(new SecurityAuditLog { EventType = SecurityEventType.LoginFailed, Timestamp = day2.AddHours(3), IsSuccess = false });
        logs.Add(new SecurityAuditLog { EventType = SecurityEventType.AccountLocked, Timestamp = day2.AddHours(4), IsSuccess = true });

        _mockSecurityAuditRepository
            .Setup(x => x.GetByDateRangeAsync(startDate, endDate))
            .ReturnsAsync(logs);

        // Act
        var result = await _sut.GetSecurityStatisticsAsync(startDate, endDate);

        // Assert
        var resultList = result.ToList();
        Assert.Equal(2, resultList.Count); // Dois dias com estatísticas
        
        // Verificar estatísticas do dia 1
        var day1Stats = resultList.FirstOrDefault(s => s.StartDate.Date == day1.Date);
        Assert.NotNull(day1Stats);
        Assert.Equal(3, day1Stats.TotalLoginAttempts); // 2 sucesso + 1 falha
        Assert.Equal(2, day1Stats.SuccessfulLogins);
        Assert.Equal(1, day1Stats.FailedLogins);
        Assert.Equal(0, day1Stats.AccountLockouts);
        
        // Verificar estatísticas do dia 2
        var day2Stats = resultList.FirstOrDefault(s => s.StartDate.Date == day2.Date);
        Assert.NotNull(day2Stats);
        Assert.Equal(3, day2Stats.TotalLoginAttempts); // 1 sucesso + 2 falhas
        Assert.Equal(1, day2Stats.SuccessfulLogins);
        Assert.Equal(2, day2Stats.FailedLogins);
        Assert.Equal(1, day2Stats.AccountLockouts);
    }

    [Fact]
    public async Task CheckForBruteForceAttack_ShouldDetectBruteForce()
    {
        // Arrange
        var userId = "user123";
        var ipAddress = "192.168.1.1";
        var timeWindow = TimeSpan.FromMinutes(15);
        
        // Simular 5 tentativas falhas de login no período (que é o limite)
        _mockSecurityAuditRepository
            .Setup(x => x.GetFailedLoginAttemptsInPeriodAsync(userId, ipAddress, It.IsAny<TimeSpan>()))
            .ReturnsAsync(5);
        
        _mockSecurityAuditRepository
            .Setup(x => x.LogEventAsync(It.IsAny<SecurityAuditLog>()))
            .ReturnsAsync(true);
        
        var user = new ApplicationUser { Id = userId };
        _mockUserRepository
            .Setup(x => x.GetByIdAsync(userId))
            .ReturnsAsync(user);
        
        _mockUserRepository
            .Setup(x => x.UpdateAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(true);

        // Act
        var result = await _sut.CheckForBruteForceAttackAsync(userId, ipAddress);

        // Assert
        Assert.True(result);
        
        // Verificar se o evento de força bruta foi registrado
        _mockSecurityAuditRepository.Verify(
            x => x.LogEventAsync(It.Is<SecurityAuditLog>(log =>
                log.EventType == SecurityEventType.BruteForceDetected &&
                log.UserId == userId &&
                log.IpAddress == ipAddress
            )),
            Times.Once
        );
        
        // Verificar se a conta foi bloqueada
        _mockUserRepository.Verify(
            x => x.UpdateAsync(It.Is<ApplicationUser>(u =>
                u.Id == userId && u.LockoutEnd.HasValue
            )),
            Times.Once
        );
    }

    [Fact]
    public async Task CheckForBruteForceAttack_ShouldNotDetectBruteForce_WhenAttemptsAreBelowThreshold()
    {
        // Arrange
        var userId = "user123";
        var ipAddress = "192.168.1.1";
        
        // Simular apenas 3 tentativas falhas de login no período (abaixo do limite)
        _mockSecurityAuditRepository
            .Setup(x => x.GetFailedLoginAttemptsInPeriodAsync(userId, ipAddress, It.IsAny<TimeSpan>()))
            .ReturnsAsync(3);

        // Act
        var result = await _sut.CheckForBruteForceAttackAsync(userId, ipAddress);

        // Assert
        Assert.False(result);
        
        // Verificar que nenhum evento de força bruta foi registrado
        _mockSecurityAuditRepository.Verify(
            x => x.LogEventAsync(It.Is<SecurityAuditLog>(log =>
                log.EventType == SecurityEventType.BruteForceDetected
            )),
            Times.Never
        );
        
        // Verificar que nenhuma conta foi bloqueada
        _mockUserRepository.Verify(
            x => x.UpdateAsync(It.IsAny<ApplicationUser>()),
            Times.Never
        );
    }
}
