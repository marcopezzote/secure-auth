using System;

namespace SecureAuth.Core.Domain.Entities;

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
    AccountLocked,
    AccountUnlocked,
    MfaEnabled,
    MfaDisabled,
    MfaVerified,
    TokenRefreshed,
    TokenRevoked,
    UserRegistered,
    UserDeleted,
    RoleAssigned,
    RoleRemoved,
    AccessDenied,
    BruteForceDetected
}
