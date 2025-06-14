using System.ComponentModel.DataAnnotations;

namespace SecureAuth.Core.Application.DTOs;

/// <summary>
/// DTO para revogar token
/// </summary>
public class RevokeTokenDto
{
    [Required(ErrorMessage = "Token é obrigatório")]
    public string Token { get; set; } = string.Empty;
}
