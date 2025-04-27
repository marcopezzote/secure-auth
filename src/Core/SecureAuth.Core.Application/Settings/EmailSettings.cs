namespace SecureAuth.Core.Application.Settings;

/// <summary>
/// Configurações para o serviço de e-mail
/// </summary>
public class EmailSettings
{
    /// <summary>
    /// Endereço de e-mail do remetente
    /// </summary>
    public string FromEmail { get; set; }
    
    /// <summary>
    /// Nome do remetente
    /// </summary>
    public string FromName { get; set; }
    
    /// <summary>
    /// Host do servidor SMTP
    /// </summary>
    public string SmtpHost { get; set; }
    
    /// <summary>
    /// Porta do servidor SMTP
    /// </summary>
    public int SmtpPort { get; set; }
    
    /// <summary>
    /// Usuário para autenticação SMTP
    /// </summary>
    public string SmtpUser { get; set; }
    
    /// <summary>
    /// Senha para autenticação SMTP
    /// </summary>
    public string SmtpPass { get; set; }
    
    /// <summary>
    /// Indica se SSL deve ser usado
    /// </summary>
    public bool UseSsl { get; set; }
}
