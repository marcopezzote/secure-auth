using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SecureAuth.Core.Domain.Entities;
using SecureAuth.Core.Domain.Interfaces;
using SecureAuth.Infrastructure.Identity.Models;

namespace SecureAuth.Infrastructure.Identity.Repositories;

/// <summary>
/// Implementação do repositório de papéis com o Identity
/// </summary>
public class RoleRepository : IRoleRepository
{
    private readonly RoleManager<ApplicationIdentityRole> _roleManager;
    private readonly UserManager<ApplicationIdentityUser> _userManager;

    public RoleRepository(
        RoleManager<ApplicationIdentityRole> roleManager,
        UserManager<ApplicationIdentityUser> userManager)
    {
        _roleManager = roleManager;
        _userManager = userManager;
    }

    /// <summary>
    /// Obtém um papel pelo ID
    /// </summary>
    public async Task<ApplicationRole> GetByIdAsync(string id)
    {
        var identityRole = await _roleManager.FindByIdAsync(id);
        if (identityRole == null)
        {
            return null;
        }

        return MapToApplicationRole(identityRole);
    }

    /// <summary>
    /// Obtém um papel pelo nome
    /// </summary>
    public async Task<ApplicationRole> GetByNameAsync(string name)
    {
        var identityRole = await _roleManager.FindByNameAsync(name);
        if (identityRole == null)
        {
            return null;
        }

        return MapToApplicationRole(identityRole);
    }

    /// <summary>
    /// Obtém todos os papéis
    /// </summary>
    public async Task<IEnumerable<ApplicationRole>> GetAllAsync()
    {
        var identityRoles = await _roleManager.Roles.ToListAsync();
        var roles = new List<ApplicationRole>();

        foreach (var identityRole in identityRoles)
        {
            roles.Add(MapToApplicationRole(identityRole));
        }

        return roles;
    }

    /// <summary>
    /// Cria um novo papel
    /// </summary>
    public async Task<bool> CreateAsync(ApplicationRole role)
    {
        var identityRole = new ApplicationIdentityRole
        {
            Id = role.Id,
            Name = role.Name,
            NormalizedName = role.NormalizedName ?? role.Name.ToUpper(),
            Description = role.Description
        };

        var result = await _roleManager.CreateAsync(identityRole);
        return result.Succeeded;
    }

    /// <summary>
    /// Atualiza um papel existente
    /// </summary>
    public async Task<bool> UpdateAsync(ApplicationRole role)
    {
        var identityRole = await _roleManager.FindByIdAsync(role.Id);
        if (identityRole == null)
        {
            return false;
        }

        identityRole.Name = role.Name;
        identityRole.NormalizedName = role.NormalizedName ?? role.Name.ToUpper();
        identityRole.Description = role.Description;

        var result = await _roleManager.UpdateAsync(identityRole);
        return result.Succeeded;
    }

    /// <summary>
    /// Exclui um papel
    /// </summary>
    public async Task<bool> DeleteAsync(string id)
    {
        var identityRole = await _roleManager.FindByIdAsync(id);
        if (identityRole == null)
        {
            return false;
        }

        var result = await _roleManager.DeleteAsync(identityRole);
        return result.Succeeded;
    }

    /// <summary>
    /// Obtém os papéis de um usuário
    /// </summary>
    public async Task<IEnumerable<ApplicationRole>> GetUserRolesAsync(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return new List<ApplicationRole>();
        }

        var roleNames = await _userManager.GetRolesAsync(user);
        var roles = new List<ApplicationRole>();

        foreach (var roleName in roleNames)
        {
            var identityRole = await _roleManager.FindByNameAsync(roleName);
            if (identityRole != null)
            {
                roles.Add(MapToApplicationRole(identityRole));
            }
        }

        return roles;
    }

    /// <summary>
    /// Atribui um papel a um usuário
    /// </summary>
    public async Task<bool> AssignRoleToUserAsync(string userId, string roleId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return false;
        }

        var role = await _roleManager.FindByIdAsync(roleId);
        if (role == null)
        {
            return false;
        }

        var result = await _userManager.AddToRoleAsync(user, role.Name);
        return result.Succeeded;
    }

    /// <summary>
    /// Remove um papel de um usuário
    /// </summary>
    public async Task<bool> RemoveRoleFromUserAsync(string userId, string roleId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return false;
        }

        var role = await _roleManager.FindByIdAsync(roleId);
        if (role == null)
        {
            return false;
        }

        var result = await _userManager.RemoveFromRoleAsync(user, role.Name);
        return result.Succeeded;
    }

    /// <summary>
    /// Converte um papel do Identity para o modelo de domínio
    /// </summary>
    private ApplicationRole MapToApplicationRole(ApplicationIdentityRole identityRole)
    {
        return new ApplicationRole
        {
            Id = identityRole.Id,
            Name = identityRole.Name,
            NormalizedName = identityRole.NormalizedName,
            Description = identityRole.Description,
            CreatedAt = DateTime.UtcNow // Na prática, isso deveria vir do banco de dados
        };
    }
}
