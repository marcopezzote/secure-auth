using System;
using SecureAuth.Core.Domain.Entities;

namespace SecureAuth.Core.Application.DTOs;

/// <summary>
/// DTO para eventos de segurança
/// </summary>
public class SecurityEventDto
{
    public SecurityEventType EventType { get; set; }
    public string UserId { get; set; } = string.Empty;
    public string IpAddress { get; set; } = string.Empty;
    public string UserAgent { get; set; } = string.Empty;
    public bool IsSuccess { get; set; }
    public string AdditionalInfo { get; set; } = string.Empty;
}
