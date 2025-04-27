namespace SecureAuth.Core.Application.DTOs;

/// <summary>
/// DTO para login de usuário
/// </summary>
public class LoginDto
{
    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string TwoFactorCode { get; set; } = string.Empty;
    public bool RememberMe { get; set; }
}
