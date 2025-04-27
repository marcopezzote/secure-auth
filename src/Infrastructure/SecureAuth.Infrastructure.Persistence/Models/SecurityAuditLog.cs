using System;

namespace SecureAuth.Infrastructure.Persistence.Models
{
    /// <summary>
    /// Modelo de log de auditoria de segurança para persistência
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
    }
    
    /// <summary>
    /// Enum para os tipos de eventos de segurança
    /// </summary>
    public enum SecurityEventType
    {
        Login,
        LoginFailed,
        Logout,
        PasswordChanged,
        PasswordReset,
        PasswordResetRequested,
        EmailConfirmed,
        MfaEnabled,
        MfaDisabled,
        UserCreated,
        UserUpdated,
        UserDeleted,
        AccountLocked,
        AccountUnlocked
    }
}
