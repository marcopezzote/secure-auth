using System.Collections.Generic;
using System.Threading.Tasks;
using Moq;
using SecureAuth.Core.Application.DTOs;
using SecureAuth.Core.Application.Services;
using SecureAuth.Core.Domain.Entities;
using SecureAuth.Core.Domain.Interfaces;
using Xunit;

namespace SecureAuth.UnitTests.Services;

public class UserServiceTests
{
    private readonly Mock<IUserRepository> _mockUserRepository;
    private readonly Mock<IRoleRepository> _mockRoleRepository;
    private readonly Mock<ISecurityAuditRepository> _mockSecurityAuditRepository;
    private readonly UserService _sut;

    public UserServiceTests()
    {
        _mockUserRepository = new Mock<IUserRepository>();
        _mockRoleRepository = new Mock<IRoleRepository>();
        _mockSecurityAuditRepository = new Mock<ISecurityAuditRepository>();
        
        _sut = new UserService(
            _mockUserRepository.Object,
            _mockRoleRepository.Object,
            _mockSecurityAuditRepository.Object
        );
    }

    [Fact]
    public async Task GetByIdAsync_ShouldReturnUser_WhenUserExists()
    {
        // Arrange
        var userId = "user123";
        var user = new ApplicationUser
        {
            Id = userId,
            UserName = "testuser",
            Email = "test@example.com"
        };
        
        _mockUserRepository.Setup(x => x.GetByIdAsync(userId))
            .ReturnsAsync(user);
            
        _mockRoleRepository.Setup(x => x.GetUserRolesAsync(userId))
            .ReturnsAsync(new List<ApplicationRole>
            {
                new ApplicationRole { Name = "User" }
            });

        // Act
        var result = await _sut.GetByIdAsync(userId);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(userId, result.Id);
        Assert.Equal(user.UserName, result.UserName);
        Assert.Equal(user.Email, result.Email);
        Assert.Single(result.Roles);
        Assert.Contains("User", result.Roles);
    }

    [Fact]
    public async Task GetByIdAsync_ShouldReturnNull_WhenUserDoesNotExist()
    {
        // Arrange
        var userId = "nonexistent";
        _mockUserRepository.Setup(x => x.GetByIdAsync(userId))
            .ReturnsAsync((ApplicationUser)null);

        // Act
        var result = await _sut.GetByIdAsync(userId);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task GetByEmailAsync_ShouldReturnUser_WhenUserExists()
    {
        // Arrange
        var email = "test@example.com";
        var user = new ApplicationUser
        {
            Id = "user123",
            UserName = "testuser",
            Email = email
        };
        
        _mockUserRepository.Setup(x => x.GetByEmailAsync(email))
            .ReturnsAsync(user);
            
        _mockRoleRepository.Setup(x => x.GetUserRolesAsync(user.Id))
            .ReturnsAsync(new List<ApplicationRole>
            {
                new ApplicationRole { Name = "User" }
            });

        // Act
        var result = await _sut.GetByEmailAsync(email);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(user.Id, result.Id);
        Assert.Equal(user.UserName, result.UserName);
        Assert.Equal(email, result.Email);
        Assert.Single(result.Roles);
        Assert.Contains("User", result.Roles);
    }

    [Fact]
    public async Task GetAllAsync_ShouldReturnAllUsers()
    {
        // Arrange
        var users = new List<ApplicationUser>
        {
            new ApplicationUser
            {
                Id = "user1",
                UserName = "user1",
                Email = "user1@example.com"
            },
            new ApplicationUser
            {
                Id = "user2",
                UserName = "user2",
                Email = "user2@example.com"
            }
        };
        
        _mockUserRepository.Setup(x => x.GetAllAsync())
            .ReturnsAsync(users);
            
        // Configure roles for each user
        _mockRoleRepository.Setup(x => x.GetUserRolesAsync("user1"))
            .ReturnsAsync(new List<ApplicationRole>
            {
                new ApplicationRole { Name = "User" }
            });
            
        _mockRoleRepository.Setup(x => x.GetUserRolesAsync("user2"))
            .ReturnsAsync(new List<ApplicationRole>
            {
                new ApplicationRole { Name = "Admin" }
            });

        // Act
        var result = await _sut.GetAllAsync();

        // Assert
        var resultList = result as List<UserDto> ?? new List<UserDto>(result);
        Assert.Equal(2, resultList.Count);
        
        // Check first user
        Assert.Equal("user1", resultList[0].Id);
        Assert.Contains("User", resultList[0].Roles);
        
        // Check second user
        Assert.Equal("user2", resultList[1].Id);
        Assert.Contains("Admin", resultList[1].Roles);
    }

    [Fact]
    public async Task UpdateUserAsync_ShouldReturnTrue_WhenUpdateSucceeds()
    {
        // Arrange
        var userDto = new UserDto
        {
            Id = "user123",
            UserName = "updateduser",
            Email = "test@example.com",
            PhoneNumber = "+5511999998888"
        };
        
        // Mocking the existing user
        var existingUser = new ApplicationUser
        {
            Id = userDto.Id,
            UserName = "originaluser",
            Email = userDto.Email,
            PhoneNumber = null
        };
        
        _mockUserRepository.Setup(x => x.GetByIdAsync(userDto.Id))
            .ReturnsAsync(existingUser);
            
        _mockUserRepository.Setup(x => x.UpdateAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(true);

        // Act
        var result = await _sut.UpdateUserAsync(userDto);

        // Assert
        Assert.True(result);
        _mockUserRepository.Verify(
            x => x.UpdateAsync(It.Is<ApplicationUser>(u => 
                u.Id == userDto.Id && 
                u.UserName == userDto.UserName && 
                u.PhoneNumber == userDto.PhoneNumber
            )),
            Times.Once
        );
    }

    [Fact]
    public async Task UpdateUserAsync_ShouldReturnFalse_WhenUserDoesNotExist()
    {
        // Arrange
        var userDto = new UserDto
        {
            Id = "nonexistent",
            UserName = "updateduser",
            Email = "test@example.com"
        };
        
        _mockUserRepository.Setup(x => x.GetByIdAsync(userDto.Id))
            .ReturnsAsync((ApplicationUser)null);

        // Act
        var result = await _sut.UpdateUserAsync(userDto);

        // Assert
        Assert.False(result);
        _mockUserRepository.Verify(
            x => x.UpdateAsync(It.IsAny<ApplicationUser>()),
            Times.Never
        );
    }

    [Fact]
    public async Task DeleteUserAsync_ShouldReturnTrue_WhenDeleteSucceeds()
    {
        // Arrange
        var userId = "user123";
        
        _mockUserRepository.Setup(x => x.DeleteAsync(userId))
            .ReturnsAsync(true);

        // Act
        var result = await _sut.DeleteUserAsync(userId);

        // Assert
        Assert.True(result);
        _mockUserRepository.Verify(
            x => x.DeleteAsync(userId),
            Times.Once
        );
    }

    [Fact]
    public async Task AssignRoleAsync_ShouldReturnTrue_WhenAssignmentSucceeds()
    {
        // Arrange
        var userId = "user123";
        var roleName = "Admin";
        
        _mockRoleRepository.Setup(x => x.GetByNameAsync(roleName))
            .ReturnsAsync(new ApplicationRole { Id = "role123", Name = roleName });
            
        _mockRoleRepository.Setup(x => x.AssignRoleToUserAsync(userId, "role123"))
            .ReturnsAsync(true);

        // Act
        var result = await _sut.AssignRoleAsync(userId, roleName);

        // Assert
        Assert.True(result);
        _mockRoleRepository.Verify(
            x => x.AssignRoleToUserAsync(userId, "role123"),
            Times.Once
        );
    }

    [Fact]
    public async Task AssignRoleAsync_ShouldReturnFalse_WhenRoleDoesNotExist()
    {
        // Arrange
        var userId = "user123";
        var roleName = "NonexistentRole";
        
        _mockRoleRepository.Setup(x => x.GetByNameAsync(roleName))
            .ReturnsAsync((ApplicationRole)null);

        // Act
        var result = await _sut.AssignRoleAsync(userId, roleName);

        // Assert
        Assert.False(result);
        _mockRoleRepository.Verify(
            x => x.AssignRoleToUserAsync(It.IsAny<string>(), It.IsAny<string>()),
            Times.Never
        );
    }
}
