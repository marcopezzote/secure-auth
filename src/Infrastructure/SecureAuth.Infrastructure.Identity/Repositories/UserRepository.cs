using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SecureAuth.Core.Domain.Entities;
using SecureAuth.Core.Domain.Interfaces;
using SecureAuth.Infrastructure.Identity.Models;

namespace SecureAuth.Infrastructure.Identity.Repositories;

/// <summary>
/// Implementação do repositório de usuários com o Identity
/// </summary>
public class UserRepository : IUserRepository
{
    private readonly UserManager<ApplicationIdentityUser> _userManager;

    public UserRepository(UserManager<ApplicationIdentityUser> userManager)
    {
        _userManager = userManager;
    }

    /// <summary>
    /// Obtém um usuário pelo ID
    /// </summary>
    public async Task<ApplicationUser> GetByIdAsync(string id)
    {
        var identityUser = await _userManager.FindByIdAsync(id);
        if (identityUser == null)
        {
            return null;
        }

        return MapToApplicationUser(identityUser);
    }

    /// <summary>
    /// Obtém um usuário pelo e-mail
    /// </summary>
    public async Task<ApplicationUser> GetByEmailAsync(string email)
    {
        var identityUser = await _userManager.FindByEmailAsync(email);
        if (identityUser == null)
        {
            return null;
        }

        return MapToApplicationUser(identityUser);
    }

    /// <summary>
    /// Obtém um usuário pelo nome de usuário
    /// </summary>
    public async Task<ApplicationUser> GetByUserNameAsync(string userName)
    {
        var identityUser = await _userManager.FindByNameAsync(userName);
        if (identityUser == null)
        {
            return null;
        }

        return MapToApplicationUser(identityUser);
    }

    /// <summary>
    /// Obtém todos os usuários
    /// </summary>
    public async Task<IEnumerable<ApplicationUser>> GetAllAsync()
    {
        var identityUsers = await _userManager.Users.ToListAsync();
        var users = new List<ApplicationUser>();

        foreach (var identityUser in identityUsers)
        {
            users.Add(MapToApplicationUser(identityUser));
        }

        return users;
    }

    /// <summary>
    /// Cria um novo usuário
    /// </summary>
    public async Task<bool> CreateAsync(ApplicationUser user, string password)
    {
        var identityUser = new ApplicationIdentityUser
        {
            Id = user.Id,
            UserName = user.UserName,
            Email = user.Email,
            NormalizedEmail = user.NormalizedEmail ?? user.Email.ToUpper(),
            EmailConfirmed = user.EmailConfirmed,
            PhoneNumber = user.PhoneNumber,
            PhoneNumberConfirmed = user.PhoneNumberConfirmed,
            TwoFactorEnabled = user.TwoFactorEnabled,
            LockoutEnabled = user.LockoutEnabled,
            LockoutEnd = user.LockoutEnd,
            AccessFailedCount = user.AccessFailedCount,
            SecurityStamp = user.SecurityStamp ?? Guid.NewGuid().ToString(),
            MfaSecretKey = user.MfaSecretKey,
            IsMfaEnabled = user.IsMfaEnabled
        };

        var result = await _userManager.CreateAsync(identityUser, password);
        return result.Succeeded;
    }

    /// <summary>
    /// Atualiza um usuário existente
    /// </summary>
    public async Task<bool> UpdateAsync(ApplicationUser user)
    {
        var identityUser = await _userManager.FindByIdAsync(user.Id);
        if (identityUser == null)
        {
            return false;
        }

        identityUser.UserName = user.UserName;
        identityUser.Email = user.Email;
        identityUser.NormalizedEmail = user.NormalizedEmail ?? user.Email.ToUpper();
        identityUser.EmailConfirmed = user.EmailConfirmed;
        identityUser.PhoneNumber = user.PhoneNumber;
        identityUser.PhoneNumberConfirmed = user.PhoneNumberConfirmed;
        identityUser.TwoFactorEnabled = user.TwoFactorEnabled;
        identityUser.LockoutEnabled = user.LockoutEnabled;
        identityUser.LockoutEnd = user.LockoutEnd;
        identityUser.AccessFailedCount = user.AccessFailedCount;
        identityUser.SecurityStamp = user.SecurityStamp;
        identityUser.MfaSecretKey = user.MfaSecretKey;
        identityUser.IsMfaEnabled = user.IsMfaEnabled;

        var result = await _userManager.UpdateAsync(identityUser);
        return result.Succeeded;
    }

    /// <summary>
    /// Exclui um usuário
    /// </summary>
    public async Task<bool> DeleteAsync(string id)
    {
        var identityUser = await _userManager.FindByIdAsync(id);
        if (identityUser == null)
        {
            return false;
        }

        var result = await _userManager.DeleteAsync(identityUser);
        return result.Succeeded;
    }

    /// <summary>
    /// Verifica se uma senha é válida para um usuário
    /// </summary>
    public async Task<bool> CheckPasswordAsync(ApplicationUser user, string password)
    {
        var identityUser = await _userManager.FindByIdAsync(user.Id);
        if (identityUser == null)
        {
            return false;
        }

        return await _userManager.CheckPasswordAsync(identityUser, password);
    }

    /// <summary>
    /// Define a senha de um usuário
    /// </summary>
    public async Task<bool> SetPasswordAsync(ApplicationUser user, string password)
    {
        var identityUser = await _userManager.FindByIdAsync(user.Id);
        if (identityUser == null)
        {
            return false;
        }

        var token = await _userManager.GeneratePasswordResetTokenAsync(identityUser);
        var result = await _userManager.ResetPasswordAsync(identityUser, token, password);

        return result.Succeeded;
    }

    /// <summary>
    /// Confirma o e-mail de um usuário
    /// </summary>
    public async Task<bool> ConfirmEmailAsync(ApplicationUser user, string token)
    {
        var identityUser = await _userManager.FindByIdAsync(user.Id);
        if (identityUser == null)
        {
            return false;
        }

        var result = await _userManager.ConfirmEmailAsync(identityUser, token);
        return result.Succeeded;
    }

    /// <summary>
    /// Gera um token para redefinição de senha
    /// </summary>
    public async Task<string> GeneratePasswordResetTokenAsync(ApplicationUser user)
    {
        var identityUser = await _userManager.FindByIdAsync(user.Id);
        if (identityUser == null)
        {
            return null;
        }

        return await _userManager.GeneratePasswordResetTokenAsync(identityUser);
    }

    /// <summary>
    /// Redefine a senha de um usuário
    /// </summary>
    public async Task<bool> ResetPasswordAsync(ApplicationUser user, string token, string newPassword)
    {
        var identityUser = await _userManager.FindByIdAsync(user.Id);
        if (identityUser == null)
        {
            return false;
        }

        var result = await _userManager.ResetPasswordAsync(identityUser, token, newPassword);
        return result.Succeeded;
    }

    /// <summary>
    /// Verifica se um usuário tem MFA habilitado
    /// </summary>
    public async Task<bool> IsMfaEnabledAsync(string userId)
    {
        var identityUser = await _userManager.FindByIdAsync(userId);
        if (identityUser == null)
        {
            return false;
        }

        return identityUser.IsMfaEnabled;
    }

    /// <summary>
    /// Define se MFA está habilitado para um usuário
    /// </summary>
    public async Task<bool> SetMfaEnabledAsync(string userId, bool enabled, string? secretKey = null)
    {
        var identityUser = await _userManager.FindByIdAsync(userId);
        if (identityUser == null)
        {
            return false;
        }

        identityUser.IsMfaEnabled = enabled;
        if (secretKey != null)
        {
            identityUser.MfaSecretKey = secretKey;
        }

        var result = await _userManager.UpdateAsync(identityUser);
        return result.Succeeded;
    }

    /// <summary>
    /// Converte um usuário do Identity para o modelo de domínio
    /// </summary>
    private ApplicationUser MapToApplicationUser(ApplicationIdentityUser identityUser)
    {
        return new ApplicationUser
        {
            Id = identityUser.Id,
            UserName = identityUser.UserName,
            Email = identityUser.Email,
            NormalizedEmail = identityUser.NormalizedEmail,
            EmailConfirmed = identityUser.EmailConfirmed,
            PasswordHash = identityUser.PasswordHash,
            PhoneNumber = identityUser.PhoneNumber,
            PhoneNumberConfirmed = identityUser.PhoneNumberConfirmed,
            TwoFactorEnabled = identityUser.TwoFactorEnabled,
            SecurityStamp = identityUser.SecurityStamp,
            LockoutEnabled = identityUser.LockoutEnabled,
            LockoutEnd = identityUser.LockoutEnd,
            AccessFailedCount = identityUser.AccessFailedCount,
            MfaSecretKey = identityUser.MfaSecretKey,
            IsMfaEnabled = identityUser.IsMfaEnabled
        };
    }
}
