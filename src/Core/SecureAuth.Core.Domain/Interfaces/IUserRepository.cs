using System.Collections.Generic;
using System.Threading.Tasks;
using SecureAuth.Core.Domain.Entities;

namespace SecureAuth.Core.Domain.Interfaces;

/// <summary>
/// Interface para repositório de usuários
/// </summary>
public interface IUserRepository
{
    Task<ApplicationUser> GetByIdAsync(string id);
    Task<ApplicationUser> GetByEmailAsync(string email);
    Task<ApplicationUser> GetByUserNameAsync(string userName);
    Task<IEnumerable<ApplicationUser>> GetAllAsync();
    Task<bool> CreateAsync(ApplicationUser user, string password);
    Task<bool> UpdateAsync(ApplicationUser user);
    Task<bool> DeleteAsync(string id);
    Task<bool> CheckPasswordAsync(ApplicationUser user, string password);
    Task<string> GenerateEmailConfirmationTokenAsync(ApplicationUser user);
    Task<bool> ConfirmEmailAsync(ApplicationUser user, string token);
    Task<string> GeneratePasswordResetTokenAsync(ApplicationUser user);
    Task<bool> ResetPasswordAsync(ApplicationUser user, string token, string newPassword);
    Task<bool> ChangePasswordAsync(ApplicationUser user, string currentPassword, string newPassword);
    Task<bool> SetLockoutEndDateAsync(ApplicationUser user, System.DateTimeOffset? lockoutEnd);
    Task<bool> SetMfaEnabledAsync(string userId, bool enabled, string secretKey = null);
    Task<bool> IsMfaEnabledAsync(string userId);
    Task<int> IncrementAccessFailedCountAsync(ApplicationUser user);
    Task<int> ResetAccessFailedCountAsync(ApplicationUser user);
    Task<System.DateTimeOffset?> GetLockoutEndDateAsync(ApplicationUser user);
    Task<int> GetAccessFailedCountAsync(ApplicationUser user);
}
