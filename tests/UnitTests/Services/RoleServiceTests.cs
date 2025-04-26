using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Moq;
using SecureAuth.Core.Application.DTOs;
using SecureAuth.Core.Application.Services;
using SecureAuth.Core.Domain.Entities;
using SecureAuth.Core.Domain.Interfaces;
using Xunit;

namespace SecureAuth.UnitTests.Services;

public class RoleServiceTests
{
    private readonly Mock<IRoleRepository> _mockRoleRepository;
    private readonly Mock<IUserRepository> _mockUserRepository;
    private readonly RoleService _sut;

    public RoleServiceTests()
    {
        _mockRoleRepository = new Mock<IRoleRepository>();
        _mockUserRepository = new Mock<IUserRepository>();
        _sut = new RoleService(_mockRoleRepository.Object, _mockUserRepository.Object);
    }

    [Fact]
    public async Task GetByIdAsync_ShouldReturnRole_WhenRoleExists()
    {
        // Arrange
        var roleId = "role123";
        var role = new ApplicationRole
        {
            Id = roleId,
            Name = "Admin",
            Description = "Administrator role"
        };
        
        _mockRoleRepository.Setup(x => x.GetByIdAsync(roleId))
            .ReturnsAsync(role);

        // Act
        var result = await _sut.GetByIdAsync(roleId);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(roleId, result.Id);
        Assert.Equal(role.Name, result.Name);
        Assert.Equal(role.Description, result.Description);
    }

    [Fact]
    public async Task GetByIdAsync_ShouldReturnNull_WhenRoleDoesNotExist()
    {
        // Arrange
        var roleId = "nonexistent";
        _mockRoleRepository.Setup(x => x.GetByIdAsync(roleId))
            .ReturnsAsync((ApplicationRole)null);

        // Act
        var result = await _sut.GetByIdAsync(roleId);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task GetByNameAsync_ShouldReturnRole_WhenRoleExists()
    {
        // Arrange
        var roleName = "Admin";
        var role = new ApplicationRole
        {
            Id = "role123",
            Name = roleName,
            Description = "Administrator role"
        };
        
        _mockRoleRepository.Setup(x => x.GetByNameAsync(roleName))
            .ReturnsAsync(role);

        // Act
        var result = await _sut.GetByNameAsync(roleName);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(role.Id, result.Id);
        Assert.Equal(roleName, result.Name);
        Assert.Equal(role.Description, result.Description);
    }

    [Fact]
    public async Task GetAllAsync_ShouldReturnAllRoles()
    {
        // Arrange
        var roles = new List<ApplicationRole>
        {
            new ApplicationRole
            {
                Id = "role1",
                Name = "Admin",
                Description = "Administrator role"
            },
            new ApplicationRole
            {
                Id = "role2",
                Name = "User",
                Description = "Regular user role"
            }
        };
        
        _mockRoleRepository.Setup(x => x.GetAllAsync())
            .ReturnsAsync(roles);

        // Act
        var result = await _sut.GetAllAsync();

        // Assert
        var resultList = result as List<RoleDto> ?? new List<RoleDto>(result);
        Assert.Equal(2, resultList.Count);
        Assert.Equal("Admin", resultList[0].Name);
        Assert.Equal("User", resultList[1].Name);
    }

    [Fact]
    public async Task CreateAsync_ShouldReturnTrue_WhenRoleCreationSucceeds()
    {
        // Arrange
        var roleDto = new RoleDto
        {
            Name = "NewRole",
            Description = "A new role"
        };
        
        _mockRoleRepository.Setup(x => x.GetByNameAsync(roleDto.Name))
            .ReturnsAsync((ApplicationRole)null);
            
        _mockRoleRepository.Setup(x => x.CreateAsync(It.IsAny<ApplicationRole>()))
            .ReturnsAsync(true);

        // Act
        var result = await _sut.CreateAsync(roleDto);

        // Assert
        Assert.True(result);
        _mockRoleRepository.Verify(
            x => x.CreateAsync(It.Is<ApplicationRole>(r => 
                r.Name == roleDto.Name && 
                r.Description == roleDto.Description
            )),
            Times.Once
        );
    }

    [Fact]
    public async Task CreateAsync_ShouldReturnFalse_WhenRoleAlreadyExists()
    {
        // Arrange
        var roleDto = new RoleDto
        {
            Name = "ExistingRole",
            Description = "An existing role"
        };
        
        _mockRoleRepository.Setup(x => x.GetByNameAsync(roleDto.Name))
            .ReturnsAsync(new ApplicationRole { Name = roleDto.Name });

        // Act
        var result = await _sut.CreateAsync(roleDto);

        // Assert
        Assert.False(result);
        _mockRoleRepository.Verify(
            x => x.CreateAsync(It.IsAny<ApplicationRole>()),
            Times.Never
        );
    }

    [Fact]
    public async Task UpdateAsync_ShouldReturnTrue_WhenUpdateSucceeds()
    {
        // Arrange
        var roleDto = new RoleDto
        {
            Id = "role123",
            Name = "UpdatedRole",
            Description = "Updated description"
        };
        
        _mockRoleRepository.Setup(x => x.GetByIdAsync(roleDto.Id))
            .ReturnsAsync(new ApplicationRole { Id = roleDto.Id, Name = "OldName" });
            
        _mockRoleRepository.Setup(x => x.GetByNameAsync(roleDto.Name))
            .ReturnsAsync((ApplicationRole)null);
            
        _mockRoleRepository.Setup(x => x.UpdateAsync(It.IsAny<ApplicationRole>()))
            .ReturnsAsync(true);

        // Act
        var result = await _sut.UpdateAsync(roleDto);

        // Assert
        Assert.True(result);
        _mockRoleRepository.Verify(
            x => x.UpdateAsync(It.Is<ApplicationRole>(r => 
                r.Id == roleDto.Id && 
                r.Name == roleDto.Name && 
                r.Description == roleDto.Description
            )),
            Times.Once
        );
    }

    [Fact]
    public async Task UpdateAsync_ShouldReturnFalse_WhenRoleDoesNotExist()
    {
        // Arrange
        var roleDto = new RoleDto
        {
            Id = "nonexistent",
            Name = "UpdatedRole",
            Description = "Updated description"
        };
        
        _mockRoleRepository.Setup(x => x.GetByIdAsync(roleDto.Id))
            .ReturnsAsync((ApplicationRole)null);

        // Act
        var result = await _sut.UpdateAsync(roleDto);

        // Assert
        Assert.False(result);
        _mockRoleRepository.Verify(
            x => x.UpdateAsync(It.IsAny<ApplicationRole>()),
            Times.Never
        );
    }

    [Fact]
    public async Task UpdateAsync_ShouldReturnFalse_WhenNameAlreadyExistsInDifferentRole()
    {
        // Arrange
        var roleDto = new RoleDto
        {
            Id = "role123",
            Name = "ExistingRole",
            Description = "Updated description"
        };
        
        _mockRoleRepository.Setup(x => x.GetByIdAsync(roleDto.Id))
            .ReturnsAsync(new ApplicationRole { Id = roleDto.Id, Name = "OldName" });
            
        _mockRoleRepository.Setup(x => x.GetByNameAsync(roleDto.Name))
            .ReturnsAsync(new ApplicationRole { Id = "differentRole", Name = roleDto.Name });

        // Act
        var result = await _sut.UpdateAsync(roleDto);

        // Assert
        Assert.False(result);
        _mockRoleRepository.Verify(
            x => x.UpdateAsync(It.IsAny<ApplicationRole>()),
            Times.Never
        );
    }

    [Fact]
    public async Task DeleteAsync_ShouldReturnTrue_WhenDeleteSucceeds()
    {
        // Arrange
        var roleId = "role123";
        
        _mockRoleRepository.Setup(x => x.DeleteAsync(roleId))
            .ReturnsAsync(true);

        // Act
        var result = await _sut.DeleteAsync(roleId);

        // Assert
        Assert.True(result);
        _mockRoleRepository.Verify(
            x => x.DeleteAsync(roleId),
            Times.Once
        );
    }

    [Fact]
    public async Task GetUsersInRoleAsync_ShouldReturnUsers_WhenRoleExists()
    {
        // Arrange
        var roleName = "Admin";
        var role = new ApplicationRole { Id = "role123", Name = roleName };
        var users = new List<ApplicationUser>
        {
            new ApplicationUser { Id = "user1", UserName = "admin1", Email = "admin1@example.com" },
            new ApplicationUser { Id = "user2", UserName = "admin2", Email = "admin2@example.com" }
        };
        
        _mockRoleRepository.Setup(x => x.GetByNameAsync(roleName))
            .ReturnsAsync(role);
            
        _mockUserRepository.Setup(x => x.GetAllAsync())
            .ReturnsAsync(users);
            
        // Configure user roles
        foreach (var user in users)
        {
            _mockRoleRepository.Setup(x => x.GetUserRolesAsync(user.Id))
                .ReturnsAsync(new List<ApplicationRole> { role });
        }

        // Act
        var result = await _sut.GetUsersInRoleAsync(roleName);

        // Assert
        var resultList = result as List<UserDto> ?? new List<UserDto>(result);
        Assert.Equal(2, resultList.Count);
        Assert.Equal("user1", resultList[0].Id);
        Assert.Equal("user2", resultList[1].Id);
    }

    [Fact]
    public async Task GetUsersInRoleAsync_ShouldReturnEmptyList_WhenRoleDoesNotExist()
    {
        // Arrange
        var roleName = "NonexistentRole";
        
        _mockRoleRepository.Setup(x => x.GetByNameAsync(roleName))
            .ReturnsAsync((ApplicationRole)null);

        // Act
        var result = await _sut.GetUsersInRoleAsync(roleName);

        // Assert
        Assert.Empty(result);
    }
}
