using System.ComponentModel.DataAnnotations;

namespace SecureAuth.Core.Application.DTOs;

/// <summary>
/// DTO para solicitação de esqueci minha senha
/// </summary>
public class ForgotPasswordDto
{
    [Required(ErrorMessage = "Email é obrigatório")]
    [EmailAddress(ErrorMessage = "Email deve ter um formato válido")]
    public string Email { get; set; } = string.Empty;
}
