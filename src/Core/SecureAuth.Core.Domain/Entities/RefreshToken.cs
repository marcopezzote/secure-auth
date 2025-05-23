using System;

namespace SecureAuth.Core.Domain.Entities;

/// <summary>
/// Entidade para refresh tokens
/// </summary>
public class RefreshToken
{
    public int Id { get; set; }
    public string UserId { get; set; }
    public string Token { get; set; }
    public DateTime ExpiryDate { get; set; }
    public DateTime Created { get; set; }
    public string CreatedByIp { get; set; }
    public DateTime? Revoked { get; set; }
    public string RevokedByIp { get; set; }
    public string ReplacedByToken { get; set; }
    public string ReasonRevoked { get; set; }
    
    public bool IsExpired => DateTime.UtcNow >= ExpiryDate;
    public bool IsRevoked => Revoked != null;
    public bool IsActive => !IsRevoked && !IsExpired;
    
    // Propriedade de navegação
    public virtual ApplicationUser User { get; set; }
}
