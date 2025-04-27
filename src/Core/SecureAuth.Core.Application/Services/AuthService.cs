using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using SecureAuth.Core.Application.DTOs;
using SecureAuth.Core.Application.Interfaces;
using SecureAuth.Core.Domain.Entities;
using SecureAuth.Core.Domain.Interfaces;

namespace SecureAuth.Core.Application.Services;

/// <summary>
/// Implementação do serviço de autenticação
/// </summary>
public class AuthService : IAuthService
{
    private readonly IUserRepository _userRepository;
    private readonly IRoleRepository _roleRepository;
    private readonly IRefreshTokenRepository _refreshTokenRepository;
    private readonly ISecurityAuditRepository _securityAuditRepository;
    private readonly IJwtService _jwtService;
    private readonly IEmailService _emailService;

    public AuthService(
        IUserRepository userRepository,
        IRoleRepository roleRepository,
        IRefreshTokenRepository refreshTokenRepository,
        ISecurityAuditRepository securityAuditRepository,
        IJwtService jwtService,
        IEmailService emailService)
    {
        _userRepository = userRepository;
        _roleRepository = roleRepository;
        _refreshTokenRepository = refreshTokenRepository;
        _securityAuditRepository = securityAuditRepository;
        _jwtService = jwtService;
        _emailService = emailService;
    }

    /// <summary>
    /// Registra um novo usuário
    /// </summary>
    public async Task<AuthResult> RegisterUserAsync(UserRegistrationDto registrationDto, string origin)
    {
        // Verificar se o e-mail já está em uso
        var existingUserByEmail = await _userRepository.GetByEmailAsync(registrationDto.Email);
        if (existingUserByEmail != null)
        {
            await LogEvent(SecurityEventType.UserRegistered, null, null, null, false, $"E-mail já em uso: {registrationDto.Email}");
            return AuthResult.Failed("E-mail já está em uso.");
        }

        // Verificar se o nome de usuário já está em uso
        var existingUserByName = await _userRepository.GetByUserNameAsync(registrationDto.UserName);
        if (existingUserByName != null)
        {
            await LogEvent(SecurityEventType.UserRegistered, null, null, null, false, $"Nome de usuário já em uso: {registrationDto.UserName}");
            return AuthResult.Failed("Nome de usuário já está em uso.");
        }

        // Criar o usuário
        var user = new ApplicationUser
        {
            UserName = registrationDto.UserName,
            Email = registrationDto.Email,
            FirstName = registrationDto.FirstName,
            LastName = registrationDto.LastName,
            EmailConfirmed = false,
            CreatedOn = DateTime.UtcNow,
            IsActive = true
        };

        // Salvar o usuário
        var result = await _userRepository.CreateAsync(user, registrationDto.Password);
        if (!result)
        {
            await LogEvent(SecurityEventType.UserRegistered, null, null, null, false, "Falha ao criar usuário");
            return AuthResult.Failed("Falha ao registrar o usuário. Por favor, tente novamente.");
        }

        // Registrar o evento de registro
        await LogEvent(SecurityEventType.UserRegistered, user.Id, string.Empty, string.Empty, true, string.Empty);

        // Atribuir o papel/função "User" por padrão
        var userRole = await _roleRepository.GetByNameAsync("User");
        if (userRole != null)
        {
            await _roleRepository.AssignRoleToUserAsync(user.Id, userRole.Id);
        }

        // Gerar token de confirmação de e-mail
        var token = await _userRepository.GenerateEmailConfirmationTokenAsync(user);
        
        // Construir link de confirmação
        var confirmationLink = $"{origin}/confirm-email?userId={user.Id}&token={Uri.EscapeDataString(token)}";
        
        // Enviar e-mail de confirmação
        await _emailService.SendEmailConfirmationAsync(user.Email, user.UserName, confirmationLink);

        return AuthResult.Success("Usuário registrado com sucesso. Verifique seu e-mail para confirmar sua conta.");
    }

    /// <summary>
    /// Faz login de um usuário
    /// </summary>
    public async Task<AuthResult> LoginAsync(LoginDto loginDto, string ipAddress, string userAgent)
    {
        // Obter o usuário pelo e-mail
        var user = await _userRepository.GetByEmailAsync(loginDto.Email);
        if (user == null)
        {
            await LogEvent(SecurityEventType.LoginFailed, null, ipAddress, userAgent, false, $"Usuário não encontrado: {loginDto.Email}");
            return AuthResult.Failed("Credenciais inválidas.");
        }

        // Verificar se a conta está bloqueada
        if (user.LockoutEnabled && user.LockoutEnd.HasValue && user.LockoutEnd > DateTimeOffset.UtcNow)
        {
            await LogEvent(SecurityEventType.LoginFailed, user.Id, ipAddress, userAgent, false, "Conta bloqueada");
            return AuthResult.LockedOut($"Sua conta está bloqueada até {user.LockoutEnd.Value.UtcDateTime.ToLocalTime()}.");
        }

        // Verificar se o e-mail foi confirmado
        if (!user.EmailConfirmed)
        {
            await LogEvent(SecurityEventType.LoginFailed, user.Id, ipAddress, userAgent, false, "E-mail não confirmado");
            return AuthResult.EmailConfirmationRequired("Por favor, confirme seu e-mail antes de fazer login.");
        }

        // Verificar a senha
        var isPasswordValid = await _userRepository.CheckPasswordAsync(user, loginDto.Password);
        if (!isPasswordValid)
        {
            // Incrementar o contador de falhas
            await _userRepository.IncrementAccessFailedCountAsync(user);
            
            await LogEvent(SecurityEventType.LoginFailed, user.Id, ipAddress, userAgent, false, "Senha inválida");
            return AuthResult.Failed("Credenciais inválidas.");
        }

        // Verificar MFA se estiver habilitado
        if (user.TwoFactorEnabled)
        {
            // Se não forneceu código MFA
            if (string.IsNullOrEmpty(loginDto.TwoFactorCode))
            {
                await LogEvent(SecurityEventType.Login, user.Id, ipAddress, userAgent, false, "MFA requerido");
                
                var mfaUserDto = new UserDto
                {
                    Id = user.Id,
                    UserName = user.UserName,
                    Email = user.Email
                    // Não incluímos informações sensíveis
                };
                
                return AuthResult.TwoFactorRequired("Código de verificação requerido.", mfaUserDto);
            }
            
            // Verificar o código MFA
            var isMfaValid = await VerifyMfaTokenAsync(user.Id, loginDto.TwoFactorCode);
            if (!isMfaValid)
            {
                await LogEvent(SecurityEventType.LoginFailed, user.Id, ipAddress, userAgent, false, "Código MFA inválido");
                return AuthResult.Failed("Código de verificação inválido.");
            }
        }

        // Login bem-sucedido - resetar contador de falhas
        await _userRepository.ResetAccessFailedCountAsync(user);
        
        // Atualizar data do último login
        user.LastLoginDate = DateTime.UtcNow;
        await _userRepository.UpdateAsync(user);
        
        // Obter papéis/funções do usuário
        var roles = await _roleRepository.GetUserRolesAsync(user.Id);
        var roleNames = roles.Select(r => r.Name).ToArray();
        
        // Gerar tokens
        var tokenResponse = await GenerateTokensAsync(user.Id, roleNames, ipAddress);
        
        await LogEvent(SecurityEventType.Login, user.Id, ipAddress, userAgent, true, string.Empty);
        
        // Criar DTO do usuário com informações básicas
        var userDto = new UserDto
        {
            Id = user.Id,
            UserName = user.UserName,
            Email = user.Email,
            FirstName = user.FirstName,
            LastName = user.LastName,
            Roles = roleNames
        };
        
        // Verifica se o token foi gerado com sucesso
        if (tokenResponse == null)
            return AuthResult.Failed("Falha ao gerar tokens de autenticação.");
            
        return AuthResult.Success("Login realizado com sucesso.", tokenResponse, userDto);
    }

    /// <summary>
    /// Atualiza um token de acesso usando um refresh token
    /// </summary>
    public async Task<AuthResult> RefreshTokenAsync(string refreshToken, string ipAddress)
    {
        var storedToken = await _refreshTokenRepository.GetByTokenAsync(refreshToken);
        
        if (storedToken == null)
        {
            await LogEvent(SecurityEventType.TokenRefreshed, null, ipAddress, null, false, "Refresh token não encontrado");
            return AuthResult.Failed("Token inválido.");
        }

        if (!storedToken.IsActive)
        {
            await LogEvent(SecurityEventType.TokenRefreshed, storedToken.UserId, ipAddress, null, false, "Refresh token inativo");
            return AuthResult.Failed("Token inválido ou expirado.");
        }
        
        // Obter o usuário
        var user = await _userRepository.GetByIdAsync(storedToken.UserId);
        if (user == null)
        {
            await LogEvent(SecurityEventType.TokenRefreshed, storedToken.UserId, ipAddress, null, false, "Usuário não encontrado");
            return AuthResult.Failed("Token inválido.");
        }

        // Revogar o token atual
        storedToken.Revoked = DateTime.UtcNow;
        storedToken.RevokedByIp = ipAddress;
        storedToken.ReasonRevoked = "Substituído por novo token";
        await _refreshTokenRepository.UpdateAsync(storedToken);

        // Gerar novos tokens
        var roles = await _roleRepository.GetUserRolesAsync(user.Id);
        var roleNames = roles.Select(r => r.Name).ToArray();
        
        var tokenResponse = await GenerateTokensAsync(user.Id, roleNames, ipAddress);
        
        // Criar DTO do usuário com informações básicas
        var userDto = new UserDto
        {
            Id = user.Id,
            UserName = user.UserName,
            Email = user.Email,
            FirstName = user.FirstName,
            LastName = user.LastName,
            Roles = roleNames
        };

        await LogEvent(SecurityEventType.TokenRefreshed, user.Id, ipAddress, string.Empty, true, string.Empty);
        
        // Verifica se o token foi gerado com sucesso
        if (tokenResponse == null)
            return AuthResult.Failed("Falha ao gerar tokens de autenticação.");
            
        return AuthResult.Success("Token renovado com sucesso.", tokenResponse, userDto);
    }

    /// <summary>
    /// Revoga um refresh token
    /// </summary>
    public async Task<bool> RevokeTokenAsync(string token, string ipAddress)
    {
        var storedToken = await _refreshTokenRepository.GetByTokenAsync(token);
        
        if (storedToken == null || !storedToken.IsActive)
            return false;

        // Revogar o token
        storedToken.Revoked = DateTime.UtcNow;
        storedToken.RevokedByIp = ipAddress;
        storedToken.ReasonRevoked = "Revogado pelo usuário";
        
        var result = await _refreshTokenRepository.UpdateAsync(storedToken);
        
        if (result)
            await LogEvent(SecurityEventType.TokenRevoked, storedToken.UserId, ipAddress, null, true, null);
            
        return result;
    }

    /// <summary>
    /// Confirma o e-mail de um usuário
    /// </summary>
    public async Task<bool> ConfirmEmailAsync(string userId, string token)
    {
        var user = await _userRepository.GetByIdAsync(userId);
        if (user == null)
            return false;

        var result = await _userRepository.ConfirmEmailAsync(user, token);
        
        if (result)
            await LogEvent(SecurityEventType.EmailConfirmed, user.Id, null, null, true, null);
            
        return result;
    }

    /// <summary>
    /// Inicia o processo de redefinição de senha
    /// </summary>
    public async Task<bool> ForgotPasswordAsync(string email, string origin)
    {
        var user = await _userRepository.GetByEmailAsync(email);
        if (user == null || !user.EmailConfirmed)
            return false; // Não revelamos que o usuário não existe

        // Gerar token de redefinição
        var token = await _userRepository.GeneratePasswordResetTokenAsync(user);
        
        // Construir link de redefinição
        var resetLink = $"{origin}/reset-password?userId={user.Id}&token={Uri.EscapeDataString(token)}";
        
        // Enviar e-mail
        var result = await _emailService.SendPasswordResetAsync(user.Email, user.UserName, resetLink);
        
        if (result)
            await LogEvent(SecurityEventType.PasswordResetRequested, user.Id, null, null, true, null);
            
        return result;
    }

    /// <summary>
    /// Redefine a senha de um usuário
    /// </summary>
    public async Task<bool> ResetPasswordAsync(ResetPasswordDto resetPasswordDto)
    {
        var user = await _userRepository.GetByIdAsync(resetPasswordDto.UserId);
        if (user == null)
            return false;

        var result = await _userRepository.ResetPasswordAsync(
            user, 
            resetPasswordDto.Token, 
            resetPasswordDto.NewPassword);
            
        if (result)
            await LogEvent(SecurityEventType.PasswordReset, user.Id, null, null, true, null);
            
        return result;
    }

    /// <summary>
    /// Altera a senha de um usuário
    /// </summary>
    public async Task<bool> ChangePasswordAsync(ChangePasswordDto changePasswordDto)
    {
        var user = await _userRepository.GetByIdAsync(changePasswordDto.UserId);
        if (user == null)
            return false;

        var result = await _userRepository.ChangePasswordAsync(
            user, 
            changePasswordDto.CurrentPassword, 
            changePasswordDto.NewPassword);
            
        if (result)
            await LogEvent(SecurityEventType.PasswordChanged, user.Id, null, null, true, null);
            
        return result;
    }

    /// <summary>
    /// Configura a autenticação de múltiplos fatores para um usuário
    /// </summary>
    public Task<MfaSetupDto> SetupMfaAsync(string userId, string issuer)
    {
        // Este método deve ser implementado no serviço de MFA na camada de infraestrutura
        // Esta é apenas uma implementação vazia que será substituída
        throw new NotImplementedException("Este método deve ser implementado na camada de infraestrutura.");
    }

    /// <summary>
    /// Verifica um token MFA
    /// </summary>
    public Task<bool> VerifyMfaTokenAsync(string userId, string token)
    {
        // Este método deve ser implementado no serviço de MFA na camada de infraestrutura
        // Esta é apenas uma implementação vazia que será substituída
        throw new NotImplementedException("Este método deve ser implementado na camada de infraestrutura.");
    }

    /// <summary>
    /// Desativa MFA para um usuário
    /// </summary>
    public async Task<bool> DisableMfaAsync(string userId, string token)
    {
        var isValid = await VerifyMfaTokenAsync(userId, token);
        if (!isValid)
            return false;

        var result = await _userRepository.SetMfaEnabledAsync(userId, false, string.Empty);
        
        if (result)
            await LogEvent(SecurityEventType.MfaDisabled, userId, null, null, true, string.Empty);
            
        return result;
    }

    /// <summary>
    /// Verifica se um usuário tem MFA habilitado
    /// </summary>
    public Task<bool> IsMfaEnabledAsync(string userId)
    {
        return _userRepository.IsMfaEnabledAsync(userId);
    }

    /// <summary>
    /// Gera tokens de acesso e atualização
    /// </summary>
    public async Task<TokenResponseDto?> GenerateTokensAsync(string userId, IEnumerable<string> roles, string ipAddress)
    {
        var user = await _userRepository.GetByIdAsync(userId);
        if (user == null)
            return null;

        // Gerar token de acesso
        var accessToken = _jwtService.GenerateAccessToken(
            user.Id,
            user.Email,
            roles.ToArray());
            
        // Gerar refresh token
        var refreshToken = _jwtService.GenerateRefreshToken();
        
        // Salvar refresh token
        var refreshTokenEntity = new RefreshToken
        {
            UserId = user.Id,
            Token = refreshToken,
            ExpiryDate = DateTime.UtcNow.AddDays(7),
            Created = DateTime.UtcNow,
            CreatedByIp = ipAddress
        };
        
        await _refreshTokenRepository.CreateAsync(refreshTokenEntity);
        
        // Criar resposta
        return new TokenResponseDto
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            ExpiresAt = _jwtService.GetTokenExpiration(accessToken)
        };
    }

    /// <summary>
    /// Valida um token de acesso
    /// </summary>
    public Task<bool> ValidateTokenAsync(string token)
    {
        // Como a validação do token é síncrona, retornamos um Task completado
        return Task.FromResult(_jwtService.ValidateToken(token));
    }

    /// <summary>
    /// Bloqueia a conta de um usuário
    /// </summary>
    public async Task<bool> LockAccountAsync(string userId)
    {
        var user = await _userRepository.GetByIdAsync(userId);
        if (user == null)
            return false;
            
        var result = await _userRepository.SetLockoutEndDateAsync(
            user, 
            DateTimeOffset.UtcNow.AddMinutes(15)); // 15 minutos de bloqueio
            
        if (result)
        {
            await LogEvent(SecurityEventType.AccountLocked, user.Id, null, null, true, null);
            
            // Notificar o usuário
            await _emailService.SendAccountLockedNotificationAsync(user.Email, user.UserName);
        }
        
        return result;
    }

    /// <summary>
    /// Desbloqueia a conta de um usuário
    /// </summary>
    public async Task<bool> UnlockAccountAsync(string userId)
    {
        var user = await _userRepository.GetByIdAsync(userId);
        if (user == null)
            return false;
            
        var result = await _userRepository.SetLockoutEndDateAsync(user, null);
        
        if (result)
            await LogEvent(SecurityEventType.AccountUnlocked, user.Id, null, null, true, null);
            
        return result;
    }

    /// <summary>
    /// Habilita MFA para um usuário
    /// </summary>
    public async Task<bool> SetMfaEnabledAsync(string userId, bool enabled)
    {
        var result = await _userRepository.SetMfaEnabledAsync(userId, enabled);
        
        if (result && enabled)
            await LogEvent(SecurityEventType.MfaEnabled, userId, string.Empty, string.Empty, true, string.Empty);
        else if (result && !enabled)
            await LogEvent(SecurityEventType.MfaDisabled, userId, string.Empty, string.Empty, true, string.Empty);
            
        return result;
    }

    // Método auxiliar para registrar eventos de segurança
    private async Task LogEvent(
        SecurityEventType eventType,
        string? userId,
        string? ipAddress,
        string? userAgent,
        bool success,
        string? additionalInfo)
    {
        var log = new SecurityAuditLog
        {
            EventType = eventType,
            UserId = userId ?? string.Empty,
            IpAddress = ipAddress ?? string.Empty,
            UserAgent = userAgent ?? string.Empty,
            IsSuccess = success,
            AdditionalInfo = additionalInfo ?? string.Empty
        };
        
        await _securityAuditRepository.LogEventAsync(log);
    }
}
