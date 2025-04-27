namespace SecureAuth.Core.Application.DTOs;

/// <summary>
/// DTO para mudança de senha
/// </summary>
public class ChangePasswordDto
{
    public string UserId { get; set; } = string.Empty;
    public string CurrentPassword { get; set; } = string.Empty;
    public string NewPassword { get; set; } = string.Empty;
    public string ConfirmNewPassword { get; set; } = string.Empty;
}
