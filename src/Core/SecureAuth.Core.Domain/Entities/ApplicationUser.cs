using System;
using System.Collections.Generic;

namespace SecureAuth.Core.Domain.Entities;

/// <summary>
/// Entidade para representar um usuário da aplicação
/// Compatível com Microsoft.AspNetCore.Identity
/// </summary>
public class ApplicationUser
{
    public string Id { get; set; } = string.Empty;
    public string UserName { get; set; } = string.Empty;
    public string NormalizedUserName { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string NormalizedEmail { get; set; } = string.Empty;
    public bool EmailConfirmed { get; set; }
    public string PasswordHash { get; set; } = string.Empty;
    public string SecurityStamp { get; set; } = string.Empty;
    public string ConcurrencyStamp { get; set; } = string.Empty;
    public string PhoneNumber { get; set; } = string.Empty;
    public bool PhoneNumberConfirmed { get; set; }
    public bool TwoFactorEnabled { get; set; }
    public DateTimeOffset? LockoutEnd { get; set; }
    public bool LockoutEnabled { get; set; }
    public int AccessFailedCount { get; set; }
    public string FirstName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
    public DateTime CreatedOn { get; set; }
    public DateTime? LastLoginDate { get; set; }
    public string MfaSecretKey { get; set; } = string.Empty;
    public bool IsActive { get; set; }
    public byte[] ProfilePicture { get; set; } = Array.Empty<byte>();
    public bool IsMfaEnabled { get; set; }
    
    // Propriedades de navegação
    public virtual ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
    public virtual ICollection<SecurityAuditLog> SecurityLogs { get; set; } = new List<SecurityAuditLog>();
}
