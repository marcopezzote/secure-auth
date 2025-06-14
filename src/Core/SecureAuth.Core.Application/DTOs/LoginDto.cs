using System.ComponentModel.DataAnnotations;

namespace SecureAuth.Core.Application.DTOs;

/// <summary>
/// DTO para login de usuário
/// </summary>
public class LoginDto
{
    [Required(ErrorMessage = "Email é obrigatório")]
    [EmailAddress(ErrorMessage = "Email deve ter um formato válido")]
    public string Email { get; set; } = string.Empty;

    [Required(ErrorMessage = "Senha é obrigatória")]
    public string Password { get; set; } = string.Empty;

    [StringLength(6, ErrorMessage = "Código de dois fatores deve ter no máximo 6 dígitos")]
    public string TwoFactorCode { get; set; } = string.Empty;

    public bool RememberMe { get; set; }
}
