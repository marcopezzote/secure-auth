using System.Collections.Generic;
using System.Threading.Tasks;
using System.Linq;
using SecureAuth.Core.Application.DTOs;
using SecureAuth.Core.Application.Interfaces;
using SecureAuth.Core.Domain.Interfaces;

namespace SecureAuth.Core.Application.Services;

/// <summary>
/// Implementação do serviço de usuários
/// </summary>
public class UserService : IUserService
{
    private readonly IUserRepository _userRepository;
    private readonly IRoleRepository _roleRepository;
    private readonly ISecurityAuditRepository _securityAuditRepository;

    public UserService(
        IUserRepository userRepository,
        IRoleRepository roleRepository,
        ISecurityAuditRepository securityAuditRepository)
    {
        _userRepository = userRepository;
        _roleRepository = roleRepository;
        _securityAuditRepository = securityAuditRepository;
    }

    /// <summary>
    /// Obtém um usuário pelo ID
    /// </summary>
    public async Task<UserDto> GetByIdAsync(string id)
    {
        var user = await _userRepository.GetByIdAsync(id);
        if (user == null)
            return null;

        var roles = await _roleRepository.GetUserRolesAsync(id);
        var roleNames = roles.Select(r => r.Name).ToArray();

        return new UserDto
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
            Roles = roleNames
        };
    }

    /// <summary>
    /// Obtém um usuário pelo e-mail
    /// </summary>
    public async Task<UserDto> GetByEmailAsync(string email)
    {
        var user = await _userRepository.GetByEmailAsync(email);
        if (user == null)
            return null;

        return await GetByIdAsync(user.Id);
    }

    /// <summary>
    /// Obtém todos os usuários
    /// </summary>
    public async Task<IEnumerable<UserDto>> GetAllAsync()
    {
        var users = await _userRepository.GetAllAsync();
        var userDtos = new List<UserDto>();

        foreach (var user in users)
        {
            var userDto = await GetByIdAsync(user.Id);
            userDtos.Add(userDto);
        }

        return userDtos;
    }

    /// <summary>
    /// Atualiza um usuário
    /// </summary>
    public async Task<bool> UpdateUserAsync(UserDto userDto)
    {
        var user = await _userRepository.GetByIdAsync(userDto.Id);
        if (user == null)
            return false;

        // Atualizar propriedades
        user.UserName = userDto.UserName;
        user.FirstName = userDto.FirstName;
        user.LastName = userDto.LastName;
        user.PhoneNumber = userDto.PhoneNumber;
        
        return await _userRepository.UpdateAsync(user);
    }

    /// <summary>
    /// Exclui um usuário
    /// </summary>
    public async Task<bool> DeleteUserAsync(string id)
    {
        return await _userRepository.DeleteAsync(id);
    }

    /// <summary>
    /// Obtém os papéis/funções de um usuário
    /// </summary>
    public async Task<IEnumerable<string>> GetUserRolesAsync(string userId)
    {
        var roles = await _roleRepository.GetUserRolesAsync(userId);
        return roles.Select(r => r.Name);
    }

    /// <summary>
    /// Atribui um papel/função a um usuário
    /// </summary>
    public async Task<bool> AssignRoleAsync(string userId, string roleName)
    {
        var role = await _roleRepository.GetByNameAsync(roleName);
        if (role == null)
            return false;

        return await _roleRepository.AssignRoleToUserAsync(userId, role.Id);
    }

    /// <summary>
    /// Remove um papel/função de um usuário
    /// </summary>
    public async Task<bool> RemoveRoleAsync(string userId, string roleName)
    {
        var role = await _roleRepository.GetByNameAsync(roleName);
        if (role == null)
            return false;

        return await _roleRepository.RemoveRoleFromUserAsync(userId, role.Id);
    }

    /// <summary>
    /// Obtém os logs de segurança de um usuário
    /// </summary>
    public async Task<IEnumerable<SecurityLogDto>> GetUserSecurityLogsAsync(string userId)
    {
        var logs = await _securityAuditRepository.GetByUserIdAsync(userId);
        
        return logs.Select(log => new SecurityLogDto
        {
            Id = log.Id,
            Timestamp = log.Timestamp,
            EventType = log.EventType,
            UserId = log.UserId,
            IpAddress = log.IpAddress,
            UserAgent = log.UserAgent,
            IsSuccess = log.IsSuccess,
            AdditionalInfo = log.AdditionalInfo
        });
    }

    /// <summary>
    /// Habilita ou desabilita MFA para um usuário
    /// </summary>
    public async Task<bool> SetMfaEnabledAsync(string userId, bool enabled)
    {
        return await _userRepository.SetMfaEnabledAsync(userId, enabled);
    }
}
