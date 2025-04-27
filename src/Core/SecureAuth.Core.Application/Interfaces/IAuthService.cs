using System.Collections.Generic;
using System.Threading.Tasks;
using SecureAuth.Core.Application.DTOs;

namespace SecureAuth.Core.Application.Interfaces;

/// <summary>
/// Interface para o serviço de autenticação
/// </summary>
public interface IAuthService
{
    Task<AuthResult> RegisterUserAsync(UserRegistrationDto registrationDto, string origin);
    Task<AuthResult> LoginAsync(LoginDto loginDto, string ipAddress, string userAgent);
    Task<AuthResult> RefreshTokenAsync(string refreshToken, string ipAddress);
    Task<bool> RevokeTokenAsync(string token, string ipAddress);
    Task<bool> ConfirmEmailAsync(string userId, string token);
    Task<bool> ForgotPasswordAsync(string email, string origin);
    Task<bool> ResetPasswordAsync(ResetPasswordDto resetPasswordDto);
    Task<bool> ChangePasswordAsync(ChangePasswordDto changePasswordDto);
    Task<MfaSetupDto> SetupMfaAsync(string userId, string issuer);
    Task<bool> VerifyMfaTokenAsync(string userId, string token);
    Task<bool> DisableMfaAsync(string userId, string token);
    Task<bool> IsMfaEnabledAsync(string userId);
    Task<TokenResponseDto?> GenerateTokensAsync(string userId, IEnumerable<string> roles, string ipAddress);
    Task<bool> ValidateTokenAsync(string token);
    Task<bool> LockAccountAsync(string userId);
    Task<bool> UnlockAccountAsync(string userId);
    Task<bool> SetMfaEnabledAsync(string userId, bool enabled);
}
