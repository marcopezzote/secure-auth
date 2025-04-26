using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Moq;
using SecureAuth.Core.Application.DTOs;
using SecureAuth.Core.Application.Interfaces;
using SecureAuth.Core.Application.Services;
using SecureAuth.Core.Domain.Entities;
using SecureAuth.Core.Domain.Interfaces;
using Xunit;

namespace SecureAuth.UnitTests.Services;

public class AuthServiceTests
{
    private readonly Mock<IUserRepository> _mockUserRepository;
    private readonly Mock<IRoleRepository> _mockRoleRepository;
    private readonly Mock<IRefreshTokenRepository> _mockRefreshTokenRepository;
    private readonly Mock<ISecurityAuditRepository> _mockSecurityAuditRepository;
    private readonly Mock<IJwtService> _mockJwtService;
    private readonly Mock<IEmailService> _mockEmailService;
    
    private readonly AuthService _sut; // System Under Test

    public AuthServiceTests()
    {
        _mockUserRepository = new Mock<IUserRepository>();
        _mockRoleRepository = new Mock<IRoleRepository>();
        _mockRefreshTokenRepository = new Mock<IRefreshTokenRepository>();
        _mockSecurityAuditRepository = new Mock<ISecurityAuditRepository>();
        _mockJwtService = new Mock<IJwtService>();
        _mockEmailService = new Mock<IEmailService>();

        _sut = new AuthService(
            _mockUserRepository.Object,
            _mockRoleRepository.Object,
            _mockRefreshTokenRepository.Object,
            _mockSecurityAuditRepository.Object,
            _mockJwtService.Object,
            _mockEmailService.Object);
    }

    [Fact]
    public async Task RegisterUserAsync_WhenEmailAlreadyExists_ReturnsFailedResult()
    {
        // Arrange
        var registrationDto = new UserRegistrationDto
        {
            Email = "test@example.com",
            UserName = "testuser",
            Password = "Password123!",
            ConfirmPassword = "Password123!"
        };
        
        _mockUserRepository.Setup(x => x.GetByEmailAsync(registrationDto.Email))
            .ReturnsAsync(new ApplicationUser { Email = registrationDto.Email });

        // Act
        var result = await _sut.RegisterUserAsync(registrationDto, "http://localhost");

        // Assert
        Assert.False(result.Succeeded);
        Assert.Contains("E-mail já está em uso", result.Message);
    }

    [Fact]
    public async Task RegisterUserAsync_WhenUserNameAlreadyExists_ReturnsFailedResult()
    {
        // Arrange
        var registrationDto = new UserRegistrationDto
        {
            Email = "test@example.com",
            UserName = "testuser",
            Password = "Password123!",
            ConfirmPassword = "Password123!"
        };
        
        _mockUserRepository.Setup(x => x.GetByEmailAsync(registrationDto.Email))
            .ReturnsAsync((ApplicationUser)null);
            
        _mockUserRepository.Setup(x => x.GetByUserNameAsync(registrationDto.UserName))
            .ReturnsAsync(new ApplicationUser { UserName = registrationDto.UserName });

        // Act
        var result = await _sut.RegisterUserAsync(registrationDto, "http://localhost");

        // Assert
        Assert.False(result.Succeeded);
        Assert.Contains("Nome de usuário já está em uso", result.Message);
    }

    [Fact]
    public async Task RegisterUserAsync_WhenAllValid_ReturnsSuccessResult()
    {
        // Arrange
        var registrationDto = new UserRegistrationDto
        {
            Email = "test@example.com",
            UserName = "testuser",
            Password = "Password123!",
            ConfirmPassword = "Password123!"
        };
        
        _mockUserRepository.Setup(x => x.GetByEmailAsync(registrationDto.Email))
            .ReturnsAsync((ApplicationUser)null);
            
        _mockUserRepository.Setup(x => x.GetByUserNameAsync(registrationDto.UserName))
            .ReturnsAsync((ApplicationUser)null);
            
        _mockUserRepository.Setup(x => x.CreateAsync(It.IsAny<ApplicationUser>(), registrationDto.Password))
            .ReturnsAsync(true);
            
        _mockRoleRepository.Setup(x => x.AssignRoleToUserAsync(It.IsAny<string>(), It.IsAny<string>()))
            .ReturnsAsync(true);
            
        _mockUserRepository.Setup(x => x.GeneratePasswordResetTokenAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync("token");
            
        _mockEmailService.Setup(x => x.SendEmailConfirmationAsync(
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
            .ReturnsAsync(true);
            
        _mockSecurityAuditRepository.Setup(x => x.LogEventAsync(It.IsAny<SecurityAuditLog>()))
            .ReturnsAsync(true);

        // Act
        var result = await _sut.RegisterUserAsync(registrationDto, "http://localhost");

        // Assert
        Assert.True(result.Succeeded);
        Assert.Contains("Usuário registrado com sucesso", result.Message);
    }

    [Fact]
    public async Task LoginAsync_WhenUserNotFound_ReturnsFailedResult()
    {
        // Arrange
        var loginDto = new LoginDto
        {
            Email = "notfound@example.com",
            Password = "Password123!"
        };
        
        _mockUserRepository.Setup(x => x.GetByEmailAsync(loginDto.Email))
            .ReturnsAsync((ApplicationUser)null);
            
        _mockSecurityAuditRepository.Setup(x => x.LogEventAsync(It.IsAny<SecurityAuditLog>()))
            .ReturnsAsync(true);

        // Act
        var result = await _sut.LoginAsync(loginDto, "127.0.0.1", "Test Agent");

        // Assert
        Assert.False(result.Succeeded);
        Assert.Contains("Credenciais inválidas", result.Message);
    }

    [Fact]
    public async Task LoginAsync_WhenAccountLocked_ReturnsLockedOutResult()
    {
        // Arrange
        var loginDto = new LoginDto
        {
            Email = "locked@example.com",
            Password = "Password123!"
        };
        
        _mockUserRepository.Setup(x => x.GetByEmailAsync(loginDto.Email))
            .ReturnsAsync(new ApplicationUser 
            { 
                Email = loginDto.Email, 
                LockoutEnabled = true,
                LockoutEnd = DateTimeOffset.UtcNow.AddMinutes(10) 
            });
            
        _mockSecurityAuditRepository.Setup(x => x.LogEventAsync(It.IsAny<SecurityAuditLog>()))
            .ReturnsAsync(true);

        // Act
        var result = await _sut.LoginAsync(loginDto, "127.0.0.1", "Test Agent");

        // Assert
        Assert.False(result.Succeeded);
        Assert.True(result.IsLockedOut);
    }

    [Fact]
    public async Task LoginAsync_WhenEmailNotConfirmed_ReturnsEmailConfirmationRequiredResult()
    {
        // Arrange
        var loginDto = new LoginDto
        {
            Email = "unconfirmed@example.com",
            Password = "Password123!"
        };
        
        _mockUserRepository.Setup(x => x.GetByEmailAsync(loginDto.Email))
            .ReturnsAsync(new ApplicationUser 
            { 
                Email = loginDto.Email, 
                EmailConfirmed = false,
                LockoutEnabled = true,
                LockoutEnd = null
            });
            
        _mockSecurityAuditRepository.Setup(x => x.LogEventAsync(It.IsAny<SecurityAuditLog>()))
            .ReturnsAsync(true);

        // Act
        var result = await _sut.LoginAsync(loginDto, "127.0.0.1", "Test Agent");

        // Assert
        Assert.False(result.Succeeded);
        Assert.True(result.RequiresEmailConfirmation);
    }

    [Fact]
    public async Task LoginAsync_WhenInvalidPassword_ReturnsFailedResult()
    {
        // Arrange
        var loginDto = new LoginDto
        {
            Email = "valid@example.com",
            Password = "WrongPassword123!"
        };
        
        var user = new ApplicationUser 
        { 
            Id = "user123",
            Email = loginDto.Email, 
            EmailConfirmed = true,
            LockoutEnabled = true,
            LockoutEnd = null
        };
        
        _mockUserRepository.Setup(x => x.GetByEmailAsync(loginDto.Email))
            .ReturnsAsync(user);
            
        _mockUserRepository.Setup(x => x.CheckPasswordAsync(user, loginDto.Password))
            .ReturnsAsync(false);
            
        _mockSecurityAuditRepository.Setup(x => x.LogEventAsync(It.IsAny<SecurityAuditLog>()))
            .ReturnsAsync(true);

        // Act
        var result = await _sut.LoginAsync(loginDto, "127.0.0.1", "Test Agent");

        // Assert
        Assert.False(result.Succeeded);
        Assert.Contains("Credenciais inválidas", result.Message);
    }

    [Fact]
    public async Task LoginAsync_WhenMfaEnabledButNoCode_ReturnsTwoFactorRequiredResult()
    {
        // Arrange
        var loginDto = new LoginDto
        {
            Email = "mfa@example.com",
            Password = "Password123!"
        };
        
        var user = new ApplicationUser 
        { 
            Id = "user123",
            Email = loginDto.Email, 
            UserName = "mfauser",
            EmailConfirmed = true,
            LockoutEnabled = true,
            LockoutEnd = null,
            TwoFactorEnabled = true
        };
        
        _mockUserRepository.Setup(x => x.GetByEmailAsync(loginDto.Email))
            .ReturnsAsync(user);
            
        _mockUserRepository.Setup(x => x.CheckPasswordAsync(user, loginDto.Password))
            .ReturnsAsync(true);
            
        _mockSecurityAuditRepository.Setup(x => x.LogEventAsync(It.IsAny<SecurityAuditLog>()))
            .ReturnsAsync(true);

        // Act
        var result = await _sut.LoginAsync(loginDto, "127.0.0.1", "Test Agent");

        // Assert
        Assert.False(result.Succeeded);
        Assert.True(result.RequiresTwoFactor);
        Assert.NotNull(result.User);
        Assert.Equal(user.Id, result.User.Id);
    }

    [Fact]
    public async Task LoginAsync_WhenAllValid_ReturnsSuccessResult()
    {
        // Arrange
        var loginDto = new LoginDto
        {
            Email = "success@example.com",
            Password = "Password123!"
        };
        
        var user = new ApplicationUser 
        { 
            Id = "user123",
            Email = loginDto.Email, 
            UserName = "successuser",
            EmailConfirmed = true,
            LockoutEnabled = true,
            LockoutEnd = null,
            TwoFactorEnabled = false,
            AccessFailedCount = 1 // Para testar reset do contador
        };
        
        _mockUserRepository.Setup(x => x.GetByEmailAsync(loginDto.Email))
            .ReturnsAsync(user);
            
        _mockUserRepository.Setup(x => x.CheckPasswordAsync(user, loginDto.Password))
            .ReturnsAsync(true);
            
        _mockUserRepository.Setup(x => x.UpdateAsync(It.Is<ApplicationUser>(u => u.AccessFailedCount == 0)))
            .ReturnsAsync(true);
            
        _mockRoleRepository.Setup(x => x.GetUserRolesAsync(user.Id))
            .ReturnsAsync(new List<ApplicationRole> 
            { 
                new ApplicationRole { Id = "role1", Name = "User" } 
            });
            
        var tokenResponse = new TokenResponseDto
        {
            AccessToken = "access-token",
            RefreshToken = "refresh-token",
            ExpiresAt = DateTime.UtcNow.AddMinutes(60)
        };
        
        _mockJwtService.Setup(x => x.GenerateAccessToken(user.Id, user.Email, It.IsAny<string[]>()))
            .Returns("access-token");
            
        _mockJwtService.Setup(x => x.GenerateRefreshToken())
            .Returns("refresh-token");
            
        _mockJwtService.Setup(x => x.GetTokenExpiration("access-token"))
            .Returns(DateTime.UtcNow.AddMinutes(60));
            
        _mockRefreshTokenRepository.Setup(x => x.CreateAsync(It.IsAny<RefreshToken>()))
            .ReturnsAsync(true);
            
        _mockSecurityAuditRepository.Setup(x => x.LogEventAsync(It.IsAny<SecurityAuditLog>()))
            .ReturnsAsync(true);

        // Act
        var result = await _sut.LoginAsync(loginDto, "127.0.0.1", "Test Agent");

        // Assert
        Assert.True(result.Succeeded);
        Assert.NotNull(result.Token);
        Assert.NotNull(result.User);
        Assert.Equal(user.Id, result.User.Id);
        Assert.Equal("access-token", result.Token.AccessToken);
        Assert.Equal("refresh-token", result.Token.RefreshToken);
    }
}
