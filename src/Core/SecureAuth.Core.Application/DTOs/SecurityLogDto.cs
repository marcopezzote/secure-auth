using System;
using SecureAuth.Core.Domain.Entities;

namespace SecureAuth.Core.Application.DTOs;

/// <summary>
/// DTO para logs de segurança
/// </summary>
public class SecurityLogDto
{
    public int Id { get; set; }
    public DateTime Timestamp { get; set; }
    public SecurityEventType EventType { get; set; }
    public string UserId { get; set; } = string.Empty;
    public string UserName { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string IpAddress { get; set; } = string.Empty;
    public string UserAgent { get; set; } = string.Empty;
    public bool IsSuccess { get; set; }
    public string AdditionalInfo { get; set; } = string.Empty;
}
