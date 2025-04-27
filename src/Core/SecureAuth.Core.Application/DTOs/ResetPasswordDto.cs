namespace SecureAuth.Core.Application.DTOs;

/// <summary>
/// DTO para redefinição de senha
/// </summary>
public class ResetPasswordDto
{
    public string UserId { get; set; } = string.Empty;
    public string Token { get; set; } = string.Empty;
    public string NewPassword { get; set; } = string.Empty;
    public string ConfirmNewPassword { get; set; } = string.Empty;
}
