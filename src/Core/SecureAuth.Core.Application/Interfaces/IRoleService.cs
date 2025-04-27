using System.Collections.Generic;
using System.Threading.Tasks;
using SecureAuth.Core.Application.DTOs;

namespace SecureAuth.Core.Application.Interfaces;

/// <summary>
/// Interface para o serviço de papéis/funções
/// </summary>
public interface IRoleService
{
    Task<RoleDto> GetByIdAsync(string id);
    Task<RoleDto> GetByNameAsync(string name);
    Task<IEnumerable<RoleDto>> GetAllAsync();
    Task<bool> CreateAsync(RoleDto roleDto);
    Task<bool> UpdateAsync(RoleDto roleDto);
    Task<bool> DeleteAsync(string id);
    Task<IEnumerable<UserDto>> GetUsersInRoleAsync(string roleName);
}
