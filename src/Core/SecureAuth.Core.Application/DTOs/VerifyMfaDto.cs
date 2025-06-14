using System.ComponentModel.DataAnnotations;

namespace SecureAuth.Core.Application.DTOs;

/// <summary>
/// DTO para verificação de token MFA
/// </summary>
public class VerifyMfaDto
{
    [Required(ErrorMessage = "UserId é obrigatório")]
    public string UserId { get; set; } = string.Empty;

    [Required(ErrorMessage = "Código MFA é obrigatório")]
    [StringLength(6, MinimumLength = 6, ErrorMessage = "Código MFA deve ter 6 dígitos")]
    public string Code { get; set; } = string.Empty;
}
