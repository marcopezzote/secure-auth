using System.Collections.Generic;
using System.Threading.Tasks;
using SecureAuth.Core.Domain.Entities;

namespace SecureAuth.Core.Domain.Interfaces;

/// <summary>
/// Interface para repositório de papéis/funções
/// </summary>
public interface IRoleRepository
{
    Task<ApplicationRole> GetByIdAsync(string id);
    Task<ApplicationRole> GetByNameAsync(string normalizedName);
    Task<IEnumerable<ApplicationRole>> GetAllAsync();
    Task<bool> CreateAsync(ApplicationRole role);
    Task<bool> UpdateAsync(ApplicationRole role);
    Task<bool> DeleteAsync(string id);
    Task<bool> AssignRoleToUserAsync(string userId, string roleId);
    Task<bool> RemoveRoleFromUserAsync(string userId, string roleId);
    Task<IEnumerable<ApplicationRole>> GetUserRolesAsync(string userId);
    Task<IEnumerable<ApplicationUser>> GetUsersInRoleAsync(string roleName);
}
