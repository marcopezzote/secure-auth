using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecureAuth.Core.Application.DTOs;
using SecureAuth.Core.Application.Interfaces;
using System.Security.Claims;

namespace SecureAuth.Web.API.Controllers;

/// <summary>
/// Controller responsável pela autenticação e autorização
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Produces("application/json")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;
    private readonly IMfaService _mfaService;
    private readonly IUserService _userService;

    public AuthController(IAuthService authService, IMfaService mfaService, IUserService userService)
    {
        _authService = authService;
        _mfaService = mfaService;
        _userService = userService;
    }

    /// <summary>
    /// Registra um novo usuário
    /// </summary>
    /// <param name="registrationDto">Dados para registro do usuário</param>
    /// <returns>Resultado da operação de registro</returns>
    /// <response code="200">Usuário registrado com sucesso</response>
    /// <response code="400">Dados inválidos ou usuário já existe</response>
    [HttpPost("register")]
    [ProducesResponseType(typeof(AuthResult), 200)]
    [ProducesResponseType(typeof(AuthResult), 400)]
    public async Task<ActionResult<AuthResult>> Register([FromBody] UserRegistrationDto registrationDto)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var origin = $"{Request.Scheme}://{Request.Host}";
        var result = await _authService.RegisterUserAsync(registrationDto, origin);

        if (result.Succeeded)
            return Ok(result);

        return BadRequest(result);
    }

    /// <summary>
    /// Realiza login do usuário
    /// </summary>
    /// <param name="loginDto">Credenciais de login</param>
    /// <returns>Resultado da operação de login</returns>
    /// <response code="200">Login realizado com sucesso</response>
    /// <response code="401">Credenciais inválidas, conta bloqueada ou email não confirmado</response>
    /// <response code="400">Dados inválidos</response>
    [HttpPost("login")]
    [ProducesResponseType(typeof(AuthResult), 200)]
    [ProducesResponseType(typeof(AuthResult), 401)]
    [ProducesResponseType(400)]
    public async Task<ActionResult<AuthResult>> Login([FromBody] LoginDto loginDto)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var ipAddress = Request.HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
        var userAgent = Request.Headers["User-Agent"].ToString();

        var result = await _authService.LoginAsync(loginDto, ipAddress, userAgent);

        if (result.Succeeded)
            return Ok(result);

        if (result.RequiresTwoFactor)
            return Ok(result); // Cliente deve enviar código MFA

        if (result.IsLockedOut)
            return Unauthorized(result);

        if (result.RequiresEmailConfirmation)
            return Unauthorized(result);

        return Unauthorized(result);
    }

    /// <summary>
    /// Renova o token de acesso usando refresh token
    /// </summary>
    /// <param name="refreshTokenDto">Refresh token</param>
    /// <returns>Novo token de acesso</returns>
    /// <response code="200">Token renovado com sucesso</response>
    /// <response code="401">Token inválido ou expirado</response>
    /// <response code="400">Dados inválidos</response>
    [HttpPost("refresh-token")]
    [ProducesResponseType(typeof(AuthResult), 200)]
    [ProducesResponseType(401)]
    [ProducesResponseType(400)]
    public async Task<ActionResult<AuthResult>> RefreshToken([FromBody] RefreshTokenDto refreshTokenDto)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var ipAddress = Request.HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
        var result = await _authService.RefreshTokenAsync(refreshTokenDto.RefreshToken, ipAddress);

        if (result.Succeeded)
        {
            return Ok(new AuthResult
            {
                Succeeded = true,
                Message = "Token renovado com sucesso",
                Token = result.Token
            });
        }

        return Unauthorized(new { message = "Token inválido ou expirado" });
    }

    /// <summary>
    /// Revoga um refresh token
    /// </summary>
    /// <param name="revokeTokenDto">Token a ser revogado</param>
    /// <returns>Resultado da operação</returns>
    /// <response code="200">Token revogado com sucesso</response>
    /// <response code="400">Falha ao revogar token ou dados inválidos</response>
    /// <response code="401">Não autorizado</response>
    [HttpPost("revoke-token")]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    [ProducesResponseType(401)]
    public async Task<IActionResult> RevokeToken([FromBody] RevokeTokenDto revokeTokenDto)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var ipAddress = Request.HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
        var result = await _authService.RevokeTokenAsync(revokeTokenDto.Token, ipAddress);

        if (result)
            return Ok(new { message = "Token revogado com sucesso" });

        return BadRequest(new { message = "Falha ao revogar token" });
    }

    /// <summary>
    /// Confirma o email do usuário
    /// </summary>
    /// <param name="userId">ID do usuário</param>
    /// <param name="token">Token de confirmação</param>
    /// <returns>Resultado da confirmação</returns>
    /// <response code="200">Email confirmado com sucesso</response>
    /// <response code="400">Parâmetros inválidos ou falha na confirmação</response>
    [HttpGet("confirm-email")]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    public async Task<IActionResult> ConfirmEmail([FromQuery] string userId, [FromQuery] string token)
    {
        if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(token))
            return BadRequest(new { message = "UserId e token são obrigatórios" });

        var result = await _authService.ConfirmEmailAsync(userId, token);

        if (result)
            return Ok(new { message = "Email confirmado com sucesso" });

        return BadRequest(new { message = "Falha na confirmação do email" });
    }

    /// <summary>
    /// Solicita redefinição de senha
    /// </summary>
    /// <param name="forgotPasswordDto">Email para redefinição</param>
    /// <returns>Resultado da solicitação</returns>
    /// <response code="200">Solicitação processada (sempre retorna sucesso por segurança)</response>
    /// <response code="400">Dados inválidos</response>
    [HttpPost("forgot-password")]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordDto forgotPasswordDto)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var origin = $"{Request.Scheme}://{Request.Host}";
        var result = await _authService.ForgotPasswordAsync(forgotPasswordDto.Email, origin);

        // Sempre retorna sucesso por motivos de segurança (não revela se o email existe)
        return Ok(new { message = "Se o email existir em nossa base, você receberá instruções para redefinir sua senha" });
    }

    /// <summary>
    /// Redefine a senha do usuário
    /// </summary>
    /// <param name="resetPasswordDto">Dados para redefinição de senha</param>
    /// <returns>Resultado da redefinição</returns>
    /// <response code="200">Senha redefinida com sucesso</response>
    /// <response code="400">Dados inválidos ou falha na redefinição</response>
    [HttpPost("reset-password")]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDto resetPasswordDto)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var result = await _authService.ResetPasswordAsync(resetPasswordDto);

        if (result)
            return Ok(new { message = "Senha redefinida com sucesso" });

        return BadRequest(new { message = "Falha na redefinição da senha" });
    }

    /// <summary>
    /// Configura autenticação de múltiplos fatores (MFA)
    /// </summary>
    /// <returns>Dados para configuração MFA (QR Code e chave manual)</returns>
    /// <response code="200">Configuração MFA retornada com sucesso</response>
    /// <response code="401">Não autorizado</response>
    [HttpGet("mfa/setup")]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    [ProducesResponseType(typeof(MfaSetupDto), 200)]
    [ProducesResponseType(401)]
    public async Task<ActionResult<MfaSetupDto>> SetupMfa()
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userId))
            return Unauthorized();

        var issuer = "SecureAuth";
        var result = await _authService.SetupMfaAsync(userId, issuer);

        return Ok(result);
    }

    /// <summary>
    /// Habilita autenticação de múltiplos fatores
    /// </summary>
    /// <param name="verifyMfaDto">Código MFA para verificação</param>
    /// <returns>Resultado da habilitação</returns>
    /// <response code="200">MFA habilitado com sucesso</response>
    /// <response code="400">Código MFA inválido ou dados inválidos</response>
    /// <response code="401">Não autorizado</response>
    [HttpPost("mfa/enable")]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    [ProducesResponseType(401)]
    public async Task<IActionResult> EnableMfa([FromBody] VerifyMfaDto verifyMfaDto)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userId))
            return Unauthorized();

        // Verificar se o código MFA está correto antes de habilitar
        var isValidCode = await _authService.VerifyMfaTokenAsync(userId, verifyMfaDto.Code);
        if (!isValidCode)
            return BadRequest(new { message = "Código MFA inválido" });

        // Habilitar MFA
        var result = await _authService.SetMfaEnabledAsync(userId, true);

        if (result)
            return Ok(new { message = "MFA habilitado com sucesso" });

        return BadRequest(new { message = "Falha ao habilitar MFA" });
    }

    /// <summary>
    /// Verifica código MFA durante o login
    /// </summary>
    /// <param name="verifyMfaDto">Dados para verificação MFA</param>
    /// <returns>Resultado da verificação e tokens se válido</returns>
    /// <response code="200">Código MFA válido, login realizado</response>
    /// <response code="401">Código MFA inválido</response>
    /// <response code="400">Dados inválidos</response>
    [HttpPost("mfa/verify")]
    [ProducesResponseType(typeof(AuthResult), 200)]
    [ProducesResponseType(typeof(AuthResult), 401)]
    [ProducesResponseType(400)]
    public async Task<ActionResult<AuthResult>> VerifyMfa([FromBody] VerifyMfaDto verifyMfaDto)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var isValid = await _authService.VerifyMfaTokenAsync(verifyMfaDto.UserId, verifyMfaDto.Code);

        if (isValid)
        {
            // Gerar tokens após verificação MFA bem-sucedida
            var ipAddress = Request.HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";

            // Obter roles do usuário
            var roles = await _userService.GetUserRolesAsync(verifyMfaDto.UserId);

            var tokenResponse = await _authService.GenerateTokensAsync(verifyMfaDto.UserId, roles, ipAddress);

            if (tokenResponse != null)
            {
                return Ok(AuthResult.Success("Login realizado com sucesso", tokenResponse));
            }
        }

        return Unauthorized(AuthResult.Failed("Código MFA inválido"));
    }

    /// <summary>
    /// Desabilita autenticação de múltiplos fatores
    /// </summary>
    /// <param name="verifyMfaDto">Código MFA para confirmação</param>
    /// <returns>Resultado da desabilitação</returns>
    /// <response code="200">MFA desabilitado com sucesso</response>
    /// <response code="400">Código inválido ou falha na desabilitação</response>
    /// <response code="401">Não autorizado</response>
    [HttpPost("mfa/disable")]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    [ProducesResponseType(401)]
    public async Task<IActionResult> DisableMfa([FromBody] VerifyMfaDto verifyMfaDto)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userId))
            return Unauthorized();

        var result = await _authService.DisableMfaAsync(userId, verifyMfaDto.Code);

        if (result)
            return Ok(new { message = "MFA desabilitado com sucesso" });

        return BadRequest(new { message = "Falha ao desabilitar MFA ou código inválido" });
    }

    /// <summary>
    /// Verifica se MFA está habilitado para o usuário
    /// </summary>
    /// <returns>Status do MFA</returns>
    /// <response code="200">Status MFA retornado com sucesso</response>
    /// <response code="401">Não autorizado</response>
    [HttpGet("mfa/status")]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    [ProducesResponseType(200)]
    [ProducesResponseType(401)]
    public async Task<ActionResult<object>> GetMfaStatus()
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userId))
            return Unauthorized();

        var isEnabled = await _authService.IsMfaEnabledAsync(userId);

        return Ok(new { mfaEnabled = isEnabled });
    }

    /// <summary>
    /// Altera a senha do usuário autenticado
    /// </summary>
    /// <param name="changePasswordDto">Dados para alteração de senha</param>
    /// <returns>Resultado da alteração</returns>
    /// <response code="200">Senha alterada com sucesso</response>
    /// <response code="400">Dados inválidos ou falha na alteração</response>
    /// <response code="401">Não autorizado</response>
    [HttpPost("change-password")]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    [ProducesResponseType(401)]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordDto changePasswordDto)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userId))
            return Unauthorized();

        // Definir o userId no DTO
        changePasswordDto.UserId = userId;

        var result = await _authService.ChangePasswordAsync(changePasswordDto);

        if (result)
            return Ok(new { message = "Senha alterada com sucesso" });

        return BadRequest(new { message = "Falha ao alterar a senha" });
    }

    /// <summary>
    /// Valida se um token JWT é válido
    /// </summary>
    /// <returns>Informações do token válido</returns>
    /// <response code="200">Token válido</response>
    /// <response code="401">Token inválido</response>
    [HttpPost("validate-token")]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    [ProducesResponseType(200)]
    [ProducesResponseType(401)]
    public ActionResult<object> ValidateToken()
    {
        // Se chegou até aqui, o token é válido (passou pela autorização)
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var userName = User.FindFirst(ClaimTypes.Name)?.Value;
        var roles = User.FindAll(ClaimTypes.Role).Select(c => c.Value).ToArray();

        return Ok(new
        {
            valid = true,
            userId = userId,
            userName = userName,
            roles = roles
        });
    }

    /// <summary>
    /// Logout do usuário (revoga refresh token)
    /// </summary>
    /// <param name="revokeTokenDto">Token a ser revogado</param>
    /// <returns>Resultado do logout</returns>
    /// <response code="200">Logout realizado com sucesso</response>
    /// <response code="400">Dados inválidos</response>
    /// <response code="401">Não autorizado</response>
    [HttpPost("logout")]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    [ProducesResponseType(200)]
    [ProducesResponseType(400)]
    [ProducesResponseType(401)]
    public async Task<IActionResult> Logout([FromBody] RevokeTokenDto revokeTokenDto)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var ipAddress = Request.HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
        await _authService.RevokeTokenAsync(revokeTokenDto.Token, ipAddress);

        return Ok(new { message = "Logout realizado com sucesso" });
    }
}
