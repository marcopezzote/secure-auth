using System.Threading.Tasks;
using SecureAuth.Core.Application.DTOs;

namespace SecureAuth.Core.Application.Interfaces;

/// <summary>
/// Interface para o serviço de e-mail
/// </summary>
public interface IEmailService
{
    Task<bool> SendEmailAsync(string to, string subject, string body, bool isHtml = true);
    Task<bool> SendEmailConfirmationAsync(string to, string username, string confirmationLink);
    Task<bool> SendPasswordResetAsync(string to, string username, string resetLink);
    Task<bool> SendAccountLockedNotificationAsync(string to, string username);
    Task<bool> SendTwoFactorCodeAsync(string to, string username, string code);
}
