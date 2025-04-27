using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using SecureAuth.Core.Application.DTOs;
using SecureAuth.Core.Application.Interfaces;
using SecureAuth.Core.Domain.Entities;
using SecureAuth.Core.Domain.Interfaces;

namespace SecureAuth.Core.Application.Services;

/// <summary>
/// Implementação do serviço de papéis/funções
/// </summary>
public class RoleService : IRoleService
{
    private readonly IRoleRepository _roleRepository;
    private readonly IUserRepository _userRepository;

    public RoleService(
        IRoleRepository roleRepository,
        IUserRepository userRepository)
    {
        _roleRepository = roleRepository;
        _userRepository = userRepository;
    }

    /// <summary>
    /// Obtém um papel/função pelo ID
    /// </summary>
    public async Task<RoleDto> GetByIdAsync(string id)
    {
        var role = await _roleRepository.GetByIdAsync(id);
        if (role == null)
            return null;

        return new RoleDto
        {
            Id = role.Id,
            Name = role.Name,
            Description = role.Description
        };
    }

    /// <summary>
    /// Obtém um papel/função pelo nome
    /// </summary>
    public async Task<RoleDto> GetByNameAsync(string name)
    {
        var role = await _roleRepository.GetByNameAsync(name);
        if (role == null)
            return null;

        return new RoleDto
        {
            Id = role.Id,
            Name = role.Name,
            Description = role.Description
        };
    }

    /// <summary>
    /// Obtém todos os papéis/funções
    /// </summary>
    public async Task<IEnumerable<RoleDto>> GetAllAsync()
    {
        var roles = await _roleRepository.GetAllAsync();
        
        return roles.Select(role => new RoleDto
        {
            Id = role.Id,
            Name = role.Name,
            Description = role.Description
        });
    }

    /// <summary>
    /// Cria um novo papel/função
    /// </summary>
    public async Task<bool> CreateAsync(RoleDto roleDto)
    {
        // Verificar se o nome já está em uso
        var existingRole = await _roleRepository.GetByNameAsync(roleDto.Name);
        if (existingRole != null)
            return false;

        var role = new ApplicationRole
        {
            Name = roleDto.Name,
            NormalizedName = roleDto.Name.ToUpperInvariant(),
            Description = roleDto.Description
        };

        return await _roleRepository.CreateAsync(role);
    }

    /// <summary>
    /// Atualiza um papel/função
    /// </summary>
    public async Task<bool> UpdateAsync(RoleDto roleDto)
    {
        var role = await _roleRepository.GetByIdAsync(roleDto.Id);
        if (role == null)
            return false;

        // Verificar se o novo nome já está em uso por outro papel/função
        if (role.Name != roleDto.Name)
        {
            var existingRole = await _roleRepository.GetByNameAsync(roleDto.Name);
            if (existingRole != null && existingRole.Id != roleDto.Id)
                return false;
        }

        // Atualizar propriedades
        role.Name = roleDto.Name;
        role.NormalizedName = roleDto.Name.ToUpperInvariant();
        role.Description = roleDto.Description;

        return await _roleRepository.UpdateAsync(role);
    }

    /// <summary>
    /// Exclui um papel/função
    /// </summary>
    public async Task<bool> DeleteAsync(string id)
    {
        return await _roleRepository.DeleteAsync(id);
    }

    /// <summary>
    /// Obtém os usuários em um papel/função
    /// </summary>
    public async Task<IEnumerable<UserDto>> GetUsersInRoleAsync(string roleName)
    {
        var role = await _roleRepository.GetByNameAsync(roleName);
        if (role == null)
            return Enumerable.Empty<UserDto>();

        var users = await _roleRepository.GetUsersInRoleAsync(roleName);
        var userDtos = new List<UserDto>();

        foreach (var user in users)
        {
            var roles = await _roleRepository.GetUserRolesAsync(user.Id);
            
            userDtos.Add(new UserDto
            {
                Id = user.Id,
                UserName = user.UserName,
                Email = user.Email,
                FirstName = user.FirstName,
                LastName = user.LastName,
                PhoneNumber = user.PhoneNumber,
                EmailConfirmed = user.EmailConfirmed,
                PhoneNumberConfirmed = user.PhoneNumberConfirmed,
                TwoFactorEnabled = user.TwoFactorEnabled,
                LockoutEnd = user.LockoutEnd?.UtcDateTime,
                LockoutEnabled = user.LockoutEnabled,
                Roles = roles.Select(r => r.Name).ToArray()
            });
        }

        return userDtos;
    }
}
