using System;
using System.Net;
using System.Net.Mail;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SecureAuth.Core.Application.Interfaces;
using SecureAuth.Core.Application.Settings;

namespace SecureAuth.Infrastructure.Identity.Services;

/// <summary>
/// Implementação do serviço de e-mail
/// </summary>
public class EmailService : IEmailService
{
    private readonly EmailSettings _emailSettings;
    private readonly ILogger<EmailService> _logger;

    public EmailService(
        IOptions<EmailSettings> emailSettings,
        ILogger<EmailService> logger)
    {
        _emailSettings = emailSettings.Value;
        _logger = logger;
    }

    /// <summary>
    /// Envia um e-mail
    /// </summary>
    public virtual async Task<bool> SendEmailAsync(string to, string subject, string body, bool isHtml = true)
    {
        try
        {
            var message = new MailMessage
            {
                From = new MailAddress(_emailSettings.FromEmail, _emailSettings.FromName),
                Subject = subject,
                Body = body,
                IsBodyHtml = isHtml
            };

            message.To.Add(new MailAddress(to));

            using var client = new SmtpClient(_emailSettings.SmtpHost, _emailSettings.SmtpPort)
            {
                EnableSsl = _emailSettings.UseSsl,
                UseDefaultCredentials = false,
                Credentials = new NetworkCredential(_emailSettings.SmtpUser, _emailSettings.SmtpPass)
            };

            await client.SendMailAsync(message);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, $"Erro ao enviar e-mail para {to}: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Envia e-mail de confirmação de conta
    /// </summary>
    public async Task<bool> SendEmailConfirmationAsync(string to, string username, string confirmationLink)
    {
        var subject = "Confirme seu endereço de e-mail";
        var body = GetEmailConfirmationTemplate(username, confirmationLink);
        
        return await SendEmailAsync(to, subject, body);
    }

    /// <summary>
    /// Envia e-mail de redefinição de senha
    /// </summary>
    public async Task<bool> SendPasswordResetAsync(string to, string username, string resetLink)
    {
        var subject = "Redefinição de senha";
        var body = GetPasswordResetTemplate(username, resetLink);
        
        return await SendEmailAsync(to, subject, body);
    }

    /// <summary>
    /// Envia notificação de bloqueio de conta
    /// </summary>
    public async Task<bool> SendAccountLockedNotificationAsync(string to, string username)
    {
        var subject = "Alerta de segurança - Conta bloqueada";
        var body = GetAccountLockedTemplate(username);
        
        return await SendEmailAsync(to, subject, body);
    }

    /// <summary>
    /// Envia código de verificação de dois fatores
    /// </summary>
    public async Task<bool> SendTwoFactorCodeAsync(string to, string username, string code)
    {
        var subject = "Seu código de verificação";
        var body = GetTwoFactorCodeTemplate(username, code);
        
        return await SendEmailAsync(to, subject, body);
    }

    // Templates de e-mail

    private string GetEmailConfirmationTemplate(string username, string confirmationLink)
    {
        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html>");
        sb.AppendLine("<head>");
        sb.AppendLine("    <style>");
        sb.AppendLine("        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }");
        sb.AppendLine("        .container { width: 100%; max-width: 600px; margin: 0 auto; padding: 20px; }");
        sb.AppendLine("        .header { background-color: #0056b3; color: #fff; padding: 20px; text-align: center; }");
        sb.AppendLine("        .content { padding: 20px; background-color: #f9f9f9; }");
        sb.AppendLine("        .button { display: inline-block; background-color: #0056b3; color: #fff; padding: 12px 20px; text-decoration: none; border-radius: 4px; }");
        sb.AppendLine("        .footer { margin-top: 20px; text-align: center; font-size: 12px; color: #666; }");
        sb.AppendLine("    </style>");
        sb.AppendLine("</head>");
        sb.AppendLine("<body>");
        sb.AppendLine("    <div class='container'>");
        sb.AppendLine("        <div class='header'>");
        sb.AppendLine("            <h1>Confirmação de E-mail</h1>");
        sb.AppendLine("        </div>");
        sb.AppendLine("        <div class='content'>");
        sb.AppendLine($"            <p>Olá {username},</p>");
        sb.AppendLine("            <p>Obrigado por criar uma conta no SecureAuth. Para completar seu registro, confirme seu endereço de e-mail clicando no botão abaixo:</p>");
        sb.AppendLine($"            <p style='text-align: center;'><a href='{confirmationLink}' class='button'>Confirmar E-mail</a></p>");
        sb.AppendLine("            <p>Se você não solicitou esta confirmação, por favor ignore este e-mail.</p>");
        sb.AppendLine("        </div>");
        sb.AppendLine("        <div class='footer'>");
        sb.AppendLine("            <p>Este é um e-mail automático. Por favor, não responda a esta mensagem.</p>");
        sb.AppendLine("        </div>");
        sb.AppendLine("    </div>");
        sb.AppendLine("</body>");
        sb.AppendLine("</html>");
        return sb.ToString();
    }

    private string GetPasswordResetTemplate(string username, string resetLink)
    {
        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html>");
        sb.AppendLine("<head>");
        sb.AppendLine("    <style>");
        sb.AppendLine("        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }");
        sb.AppendLine("        .container { width: 100%; max-width: 600px; margin: 0 auto; padding: 20px; }");
        sb.AppendLine("        .header { background-color: #0056b3; color: #fff; padding: 20px; text-align: center; }");
        sb.AppendLine("        .content { padding: 20px; background-color: #f9f9f9; }");
        sb.AppendLine("        .button { display: inline-block; background-color: #0056b3; color: #fff; padding: 12px 20px; text-decoration: none; border-radius: 4px; }");
        sb.AppendLine("        .warning { color: #dc3545; font-weight: bold; }");
        sb.AppendLine("        .footer { margin-top: 20px; text-align: center; font-size: 12px; color: #666; }");
        sb.AppendLine("    </style>");
        sb.AppendLine("</head>");
        sb.AppendLine("<body>");
        sb.AppendLine("    <div class='container'>");
        sb.AppendLine("        <div class='header'>");
        sb.AppendLine("            <h1>Redefinição de Senha</h1>");
        sb.AppendLine("        </div>");
        sb.AppendLine("        <div class='content'>");
        sb.AppendLine($"            <p>Olá {username},</p>");
        sb.AppendLine("            <p>Recebemos uma solicitação para redefinir sua senha. Clique no botão abaixo para criar uma nova senha:</p>");
        sb.AppendLine($"            <p style='text-align: center;'><a href='{resetLink}' class='button'>Redefinir Senha</a></p>");
        sb.AppendLine("            <p class='warning'>Se você não solicitou esta redefinição, por favor ignore este e-mail e verifique a segurança da sua conta.</p>");
        sb.AppendLine("            <p>Este link expirará em 24 horas.</p>");
        sb.AppendLine("        </div>");
        sb.AppendLine("        <div class='footer'>");
        sb.AppendLine("            <p>Este é um e-mail automático. Por favor, não responda a esta mensagem.</p>");
        sb.AppendLine("        </div>");
        sb.AppendLine("    </div>");
        sb.AppendLine("</body>");
        sb.AppendLine("</html>");
        return sb.ToString();
    }

    private string GetAccountLockedTemplate(string username)
    {
        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html>");
        sb.AppendLine("<head>");
        sb.AppendLine("    <style>");
        sb.AppendLine("        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }");
        sb.AppendLine("        .container { width: 100%; max-width: 600px; margin: 0 auto; padding: 20px; }");
        sb.AppendLine("        .header { background-color: #dc3545; color: #fff; padding: 20px; text-align: center; }");
        sb.AppendLine("        .content { padding: 20px; background-color: #f9f9f9; }");
        sb.AppendLine("        .alert { color: #dc3545; font-weight: bold; }");
        sb.AppendLine("        .footer { margin-top: 20px; text-align: center; font-size: 12px; color: #666; }");
        sb.AppendLine("    </style>");
        sb.AppendLine("</head>");
        sb.AppendLine("<body>");
        sb.AppendLine("    <div class='container'>");
        sb.AppendLine("        <div class='header'>");
        sb.AppendLine("            <h1>Alerta de Segurança</h1>");
        sb.AppendLine("        </div>");
        sb.AppendLine("        <div class='content'>");
        sb.AppendLine($"            <p>Olá {username},</p>");
        sb.AppendLine("            <p class='alert'>Sua conta foi temporariamente bloqueada devido a múltiplas tentativas de login malsucedidas.</p>");
        sb.AppendLine("            <p>Por motivos de segurança, sua conta permanecerá bloqueada por 15 minutos. Após este período, você poderá tentar fazer login novamente.</p>");
        sb.AppendLine("            <p>Se você não tentou fazer login recentemente, isso pode indicar que alguém está tentando acessar sua conta. Recomendamos que você altere sua senha assim que possível.</p>");
        sb.AppendLine("        </div>");
        sb.AppendLine("        <div class='footer'>");
        sb.AppendLine("            <p>Este é um e-mail automático. Por favor, não responda a esta mensagem.</p>");
        sb.AppendLine("        </div>");
        sb.AppendLine("    </div>");
        sb.AppendLine("</body>");
        sb.AppendLine("</html>");
        return sb.ToString();
    }

    private string GetTwoFactorCodeTemplate(string username, string code)
    {
        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html>");
        sb.AppendLine("<head>");
        sb.AppendLine("    <style>");
        sb.AppendLine("        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }");
        sb.AppendLine("        .container { width: 100%; max-width: 600px; margin: 0 auto; padding: 20px; }");
        sb.AppendLine("        .header { background-color: #0056b3; color: #fff; padding: 20px; text-align: center; }");
        sb.AppendLine("        .content { padding: 20px; background-color: #f9f9f9; }");
        sb.AppendLine("        .code { font-size: 32px; font-weight: bold; text-align: center; letter-spacing: 5px; margin: 20px 0; color: #0056b3; }");
        sb.AppendLine("        .footer { margin-top: 20px; text-align: center; font-size: 12px; color: #666; }");
        sb.AppendLine("    </style>");
        sb.AppendLine("</head>");
        sb.AppendLine("<body>");
        sb.AppendLine("    <div class='container'>");
        sb.AppendLine("        <div class='header'>");
        sb.AppendLine("            <h1>Seu Código de Verificação</h1>");
        sb.AppendLine("        </div>");
        sb.AppendLine("        <div class='content'>");
        sb.AppendLine($"            <p>Olá {username},</p>");
        sb.AppendLine("            <p>Seu código de verificação para login é:</p>");
        sb.AppendLine($"            <div class='code'>{code}</div>");
        sb.AppendLine("            <p>Este código expirará em 5 minutos.</p>");
        sb.AppendLine("            <p>Se você não solicitou este código, por favor ignore este e-mail e verifique a segurança da sua conta.</p>");
        sb.AppendLine("        </div>");
        sb.AppendLine("        <div class='footer'>");
        sb.AppendLine("            <p>Este é um e-mail automático. Por favor, não responda a esta mensagem.</p>");
        sb.AppendLine("        </div>");
        sb.AppendLine("    </div>");
        sb.AppendLine("</body>");
        sb.AppendLine("</html>");
        return sb.ToString();
    }
}
