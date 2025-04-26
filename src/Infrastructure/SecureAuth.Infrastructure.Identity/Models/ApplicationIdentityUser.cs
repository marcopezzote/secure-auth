using Microsoft.AspNetCore.Identity;
using System;

namespace SecureAuth.Infrastructure.Identity.Models;

/// <summary>
/// Extensão do modelo de usuário do Identity para suportar funcionalidades adicionais
/// </summary>
public class ApplicationIdentityUser : IdentityUser
{
    // Campos adicionais para MFA
    public string MfaSecretKey { get; set; }
    public bool IsMfaEnabled { get; set; }
    
    // Para rastreamento
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? LastLoginAt { get; set; }
    public string LastLoginIp { get; set; }
}
