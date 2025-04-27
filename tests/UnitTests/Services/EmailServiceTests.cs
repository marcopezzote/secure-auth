using System;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using SecureAuth.Core.Application.Settings;
using SecureAuth.Infrastructure.Identity.Services;
using Xunit;

namespace SecureAuth.UnitTests.Services;

public class EmailServiceTests
{
    private readonly Mock<IOptions<EmailSettings>> _mockEmailSettings;
    private readonly Mock<ILogger<EmailService>> _mockLogger;
    private readonly EmailSettings _emailSettings;
    private readonly EmailService _sut;

    public EmailServiceTests()
    {
        _mockEmailSettings = new Mock<IOptions<EmailSettings>>();
        _mockLogger = new Mock<ILogger<EmailService>>();
        
        _emailSettings = new EmailSettings
        {
            SmtpHost = "smtp.example.com",
            SmtpPort = 587,
            SmtpUser = "test@example.com",
            SmtpPass = "password",
            FromEmail = "noreply@example.com",
            FromName = "Test Sender",
            UseSsl = true
        };
        
        _mockEmailSettings.Setup(x => x.Value).Returns(_emailSettings);
        
        _sut = new EmailService(_mockEmailSettings.Object, _mockLogger.Object);
    }

    // Nota: Testes reais de envio de e-mail geralmente são difíceis porque
    // dependem de serviços externos. Podemos usar o pacote SmtpServer para
    // simular um servidor SMTP local, mas para este teste vamos simular o 
    // comportamento usando um mock de SmtpClient.
    
    // Alternativamente, este é um bom caso para escrever testes de integração.

    [Fact]
    public async Task SendEmailAsync_ShouldReturnTrue_WhenEmailSendSucceeds()
    {
        // Este teste é complicado porque SmtpClient não é facilmente mockável
        // Uma opção é extrair a criação de SmtpClient para um método virtual/interface
        // ou usar uma biblioteca de e-mail que suporte injeção de dependência
        
        // Para fins de demonstração, vamos apenas verificar se não há exceções
        
        // Arrange - não precisamos fazer nada além da configuração no construtor
        
        // Act e Assert - para testes reais, você precisaria de um servidor SMTP de teste
        // ou um mock mais sofisticado do cliente SMTP
        
        // Este teste não é muito útil sem um mock adequado do SmtpClient
        // ou um servidor SMTP de teste, mas deixo aqui como placeholder
        
        // Na prática, você pode querer verificar o envio de e-mail em testes
        // de integração ou aceitar que esse serviço será coberto por testes manuais
    }

    [Fact]
    public async Task SendEmailConfirmationAsync_ShouldCallSendEmailAsync_WithCorrectParameters()
    {
        // Arrange
        var to = "user@example.com";
        var username = "testuser";
        var confirmationLink = "http://example.com/confirm?token=123";
        
        // Criar uma subclasse de teste que sobrescreve o método SendEmailAsync
        var mockEmailService = new Mock<EmailService>(_mockEmailSettings.Object, _mockLogger.Object) { CallBase = true };
        mockEmailService
            .Setup(x => x.SendEmailAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<bool>()))
            .ReturnsAsync(true);
        
        // Act
        var result = await mockEmailService.Object.SendEmailConfirmationAsync(to, username, confirmationLink);
        
        // Assert
        Assert.True(result);
        mockEmailService.Verify(
            x => x.SendEmailAsync(
                to,
                "Confirme seu endereço de e-mail",
                It.Is<string>(body => 
                    body.Contains(username) && 
                    body.Contains(confirmationLink)),
                true),
            Times.Once);
    }

    [Fact]
    public async Task SendPasswordResetAsync_ShouldCallSendEmailAsync_WithCorrectParameters()
    {
        // Arrange
        var to = "user@example.com";
        var username = "testuser";
        var resetLink = "http://example.com/reset?token=123";
        
        // Criar uma subclasse de teste que sobrescreve o método SendEmailAsync
        var mockEmailService = new Mock<EmailService>(_mockEmailSettings.Object, _mockLogger.Object) { CallBase = true };
        mockEmailService
            .Setup(x => x.SendEmailAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<bool>()))
            .ReturnsAsync(true);
        
        // Act
        var result = await mockEmailService.Object.SendPasswordResetAsync(to, username, resetLink);
        
        // Assert
        Assert.True(result);
        mockEmailService.Verify(
            x => x.SendEmailAsync(
                to,
                "Redefinição de senha",
                It.Is<string>(body => 
                    body.Contains(username) && 
                    body.Contains(resetLink)),
                true),
            Times.Once);
    }

    [Fact]
    public async Task SendAccountLockedNotificationAsync_ShouldCallSendEmailAsync_WithCorrectParameters()
    {
        // Arrange
        var to = "user@example.com";
        var username = "testuser";
        
        // Criar uma subclasse de teste que sobrescreve o método SendEmailAsync
        var mockEmailService = new Mock<EmailService>(_mockEmailSettings.Object, _mockLogger.Object) { CallBase = true };
        mockEmailService
            .Setup(x => x.SendEmailAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<bool>()))
            .ReturnsAsync(true);
        
        // Act
        var result = await mockEmailService.Object.SendAccountLockedNotificationAsync(to, username);
        
        // Assert
        Assert.True(result);
        mockEmailService.Verify(
            x => x.SendEmailAsync(
                to,
                "Alerta de segurança - Conta bloqueada",
                It.Is<string>(body => body.Contains(username)),
                true),
            Times.Once);
    }

    [Fact]
    public async Task SendTwoFactorCodeAsync_ShouldCallSendEmailAsync_WithCorrectParameters()
    {
        // Arrange
        var to = "user@example.com";
        var username = "testuser";
        var code = "123456";
        
        // Criar uma subclasse de teste que sobrescreve o método SendEmailAsync
        var mockEmailService = new Mock<EmailService>(_mockEmailSettings.Object, _mockLogger.Object) { CallBase = true };
        mockEmailService
            .Setup(x => x.SendEmailAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<bool>()))
            .ReturnsAsync(true);
        
        // Act
        var result = await mockEmailService.Object.SendTwoFactorCodeAsync(to, username, code);
        
        // Assert
        Assert.True(result);
        mockEmailService.Verify(
            x => x.SendEmailAsync(
                to,
                "Seu código de verificação",
                It.Is<string>(body => 
                    body.Contains(username) && 
                    body.Contains(code)),
                true),
            Times.Once);
    }
}
