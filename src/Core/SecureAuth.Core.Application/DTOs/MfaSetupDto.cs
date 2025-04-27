namespace SecureAuth.Core.Application.DTOs;

/// <summary>
/// DTO para setup de MFA
/// </summary>
public class MfaSetupDto
{
    public string SecretKey { get; set; } = string.Empty;
    public string QrCodeBase64 { get; set; } = string.Empty;
    public string ManualEntryKey { get; set; } = string.Empty;
}
