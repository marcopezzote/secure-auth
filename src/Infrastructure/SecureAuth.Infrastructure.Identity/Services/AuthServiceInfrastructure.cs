using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SecureAuth.Core.Application.DTOs;
using SecureAuth.Core.Application.Interfaces;

namespace SecureAuth.Infrastructure.Identity.Services;

/// <summary>
/// Implementação da interface de autenticação que fornece a implementação
/// dos métodos que dependem de serviços na camada de infraestrutura
/// </summary>
public class AuthServiceInfrastructure : IAuthService
{
    private readonly IAuthService _authServiceImplementation;
    private readonly IMfaService _mfaService;
    private readonly ILogger<AuthServiceInfrastructure> _logger;

    public AuthServiceInfrastructure(
        IAuthService authServiceImplementation,
        IMfaService mfaService,
        ILogger<AuthServiceInfrastructure> logger)
    {
        _authServiceImplementation = authServiceImplementation;
        _mfaService = mfaService;
        _logger = logger;
    }

    // Métodos a serem implementados nesta camada

    /// <summary>
    /// Configura a autenticação de múltiplos fatores para um usuário
    /// </summary>
    public async Task<MfaSetupDto> SetupMfaAsync(string userId, string issuer)
    {
        try
        {
            return await _mfaService.SetupMfaAsync(userId, issuer);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, $"Erro ao configurar MFA para o usuário {userId}: {ex.Message}");
            throw;
        }
    }

    /// <summary>
    /// Verifica um token MFA
    /// </summary>
    public async Task<bool> VerifyMfaTokenAsync(string userId, string token)
    {
        try
        {
            return await _mfaService.VerifyCodeAsync(userId, token);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, $"Erro ao verificar token MFA para o usuário {userId}: {ex.Message}");
            return false;
        }
    }

    // Repasse dos demais métodos para a implementação base

    public Task<AuthResult> RegisterUserAsync(UserRegistrationDto registrationDto, string origin)
    {
        return _authServiceImplementation.RegisterUserAsync(registrationDto, origin);
    }

    public Task<AuthResult> LoginAsync(LoginDto loginDto, string ipAddress, string userAgent)
    {
        return _authServiceImplementation.LoginAsync(loginDto, ipAddress, userAgent);
    }

    public Task<AuthResult> RefreshTokenAsync(string refreshToken, string ipAddress)
    {
        return _authServiceImplementation.RefreshTokenAsync(refreshToken, ipAddress);
    }

    public Task<bool> RevokeTokenAsync(string token, string ipAddress)
    {
        return _authServiceImplementation.RevokeTokenAsync(token, ipAddress);
    }

    public Task<bool> ConfirmEmailAsync(string userId, string token)
    {
        return _authServiceImplementation.ConfirmEmailAsync(userId, token);
    }

    public Task<bool> ForgotPasswordAsync(string email, string origin)
    {
        return _authServiceImplementation.ForgotPasswordAsync(email, origin);
    }

    public Task<bool> ResetPasswordAsync(ResetPasswordDto resetPasswordDto)
    {
        return _authServiceImplementation.ResetPasswordAsync(resetPasswordDto);
    }

    public Task<bool> ChangePasswordAsync(ChangePasswordDto changePasswordDto)
    {
        return _authServiceImplementation.ChangePasswordAsync(changePasswordDto);
    }

    public Task<bool> DisableMfaAsync(string userId, string token)
    {
        return _authServiceImplementation.DisableMfaAsync(userId, token);
    }

    public Task<bool> IsMfaEnabledAsync(string userId)
    {
        return _authServiceImplementation.IsMfaEnabledAsync(userId);
    }

    public Task<TokenResponseDto> GenerateTokensAsync(string userId, System.Collections.Generic.IEnumerable<string> roles, string ipAddress)
    {
        return _authServiceImplementation.GenerateTokensAsync(userId, roles, ipAddress);
    }

    public Task<bool> ValidateTokenAsync(string token)
    {
        return _authServiceImplementation.ValidateTokenAsync(token);
    }

    public Task<bool> LockAccountAsync(string userId)
    {
        return _authServiceImplementation.LockAccountAsync(userId);
    }

    public Task<bool> UnlockAccountAsync(string userId)
    {
        return _authServiceImplementation.UnlockAccountAsync(userId);
    }
}
