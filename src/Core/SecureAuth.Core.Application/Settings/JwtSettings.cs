namespace SecureAuth.Core.Application.Settings;

/// <summary>
/// Configurações para o JWT
/// </summary>
public class JwtSettings
{
    public string Secret { get; set; }
    public string Issuer { get; set; }
    public string Audience { get; set; }
    public int ExpirationInMinutes { get; set; }
    public int RefreshTokenExpirationInDays { get; set; }
}
