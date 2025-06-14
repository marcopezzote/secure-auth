using System.ComponentModel.DataAnnotations;

namespace SecureAuth.Core.Application.DTOs;

/// <summary>
/// DTO para refresh token
/// </summary>
public class RefreshTokenDto
{
    [Required(ErrorMessage = "Refresh token é obrigatório")]
    public string RefreshToken { get; set; } = string.Empty;
}
