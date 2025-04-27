using System.Collections.Generic;
using System.Threading.Tasks;
using SecureAuth.Core.Application.DTOs;

namespace SecureAuth.Core.Application.Interfaces;

/// <summary>
/// Interface para o serviço de usuários
/// </summary>
public interface IUserService
{
    Task<UserDto> GetByIdAsync(string id);
    Task<UserDto> GetByEmailAsync(string email);
    Task<IEnumerable<UserDto>> GetAllAsync();
    Task<bool> UpdateUserAsync(UserDto userDto);
    Task<bool> DeleteUserAsync(string id);
    Task<IEnumerable<string>> GetUserRolesAsync(string userId);
    Task<bool> AssignRoleAsync(string userId, string roleName);
    Task<bool> RemoveRoleAsync(string userId, string roleName);
    Task<IEnumerable<SecurityLogDto>> GetUserSecurityLogsAsync(string userId);
    Task<bool> SetMfaEnabledAsync(string userId, bool enabled);
}
