using System;

namespace SecureAuth.Core.Domain.Entities;

/// <summary>
/// Entidade para registro de log de auditoria de segurança
/// </summary>
public class SecurityAuditLog
{
    public int Id { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public SecurityEventType EventType { get; set; }
    public string UserId { get; set; }
    public string IpAddress { get; set; }
    public string UserAgent { get; set; }
    public bool IsSuccess { get; set; }
    public string AdditionalInfo { get; set; }
    
    // Propriedade de navegação
    public virtual ApplicationUser User { get; set; }
}
