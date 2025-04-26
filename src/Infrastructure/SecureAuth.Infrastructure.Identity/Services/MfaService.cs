using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using GoogleAuthenticator;
using Microsoft.Extensions.Options;
using QRCoder;
using SecureAuth.Core.Application.DTOs;
using SecureAuth.Core.Application.Interfaces;
using SecureAuth.Core.Application.Settings;
using SecureAuth.Core.Domain.Interfaces;

namespace SecureAuth.Infrastructure.Identity.Services;

/// <summary>
/// Implementação do serviço de autenticação de dois fatores (MFA)
/// </summary>
public class MfaService : IMfaService
{
    private readonly IUserRepository _userRepository;
    private readonly MfaSettings _mfaSettings;

    public MfaService(
        IUserRepository userRepository,
        IOptions<MfaSettings> mfaSettings)
    {
        _userRepository = userRepository;
        _mfaSettings = mfaSettings.Value;
    }

    /// <summary>
    /// Configura MFA para um usuário
    /// </summary>
    public async Task<MfaSetupDto> SetupMfaAsync(string userId, string issuer)
    {
        // Obter o usuário
        var user = await _userRepository.GetByIdAsync(userId);
        if (user == null)
        {
            throw new ArgumentException("Usuário não encontrado", nameof(userId));
        }

        // Criar uma nova instância do TwoFactorAuthenticator
        var tfa = new TwoFactorAuthenticator();

        // Gerar uma chave secreta aleatória se o usuário ainda não tiver uma
        if (string.IsNullOrEmpty(user.MfaSecretKey))
        {
            user.MfaSecretKey = GenerateRandomSecretKey();
            await _userRepository.UpdateAsync(user);
        }

        // Se não for fornecido um issuer, usar o padrão
        issuer = string.IsNullOrEmpty(issuer) ? _mfaSettings.Issuer : issuer;

        // Configurar chave
        var setupInfo = tfa.GenerateSetupCode(
            issuer,
            user.Email,
            user.MfaSecretKey,
            _mfaSettings.QrCodeSize,
            _mfaSettings.QrCodeSize
        );

        // Converter QR code para base64
        string qrCodeBase64 = null;
        using (var qrGenerator = new QRCodeGenerator())
        {
            var qrCodeData = qrGenerator.CreateQrCode(setupInfo.ManualEntryKey, QRCodeGenerator.ECCLevel.Q);
            using (var qrCode = new QRCode(qrCodeData))
            {
                using (var bitmap = qrCode.GetGraphic(20))
                {
                    using (var ms = new MemoryStream())
                    {
                        bitmap.Save(ms, System.Drawing.Imaging.ImageFormat.Png);
                        qrCodeBase64 = Convert.ToBase64String(ms.ToArray());
                    }
                }
            }
        }

        // Criar e retornar DTO
        return new MfaSetupDto
        {
            SecretKey = user.MfaSecretKey,
            QrCodeBase64 = qrCodeBase64,
            ManualEntryKey = setupInfo.ManualEntryKey
        };
    }

    /// <summary>
    /// Verifica um código MFA
    /// </summary>
    public async Task<bool> VerifyCodeAsync(string userId, string code)
    {
        // Validar parâmetros
        if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(code))
        {
            return false;
        }

        // Obter o usuário
        var user = await _userRepository.GetByIdAsync(userId);
        if (user == null || string.IsNullOrEmpty(user.MfaSecretKey))
        {
            return false;
        }

        // Criar uma nova instância do TwoFactorAuthenticator
        var tfa = new TwoFactorAuthenticator();

        // Verificar o código
        return tfa.ValidateTwoFactorPIN(user.MfaSecretKey, code);
    }

    /// <summary>
    /// Ativa MFA para um usuário
    /// </summary>
    public async Task<bool> EnableMfaAsync(string userId, string code)
    {
        // Verificar se o código é válido
        var isValid = await VerifyCodeAsync(userId, code);
        if (!isValid)
        {
            return false;
        }

        // Habilitar MFA para o usuário
        return await _userRepository.SetMfaEnabledAsync(userId, true);
    }

    /// <summary>
    /// Desativa MFA para um usuário
    /// </summary>
    public async Task<bool> DisableMfaAsync(string userId, string code)
    {
        // Verificar se o código é válido
        var isValid = await VerifyCodeAsync(userId, code);
        if (!isValid)
        {
            return false;
        }

        // Desabilitar MFA para o usuário
        return await _userRepository.SetMfaEnabledAsync(userId, false, null);
    }

    /// <summary>
    /// Verifica se um usuário tem MFA habilitado
    /// </summary>
    public async Task<bool> IsMfaEnabledAsync(string userId)
    {
        return await _userRepository.IsMfaEnabledAsync(userId);
    }

    /// <summary>
    /// Gera uma chave secreta aleatória
    /// </summary>
    private string GenerateRandomSecretKey()
    {
        // Criar um array de bytes aleatório
        var key = new byte[20]; // 160 bits
        using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
        {
            rng.GetBytes(key);
        }

        // Retornar a chave em formato Base32
        return Base32Encode(key);
    }

    /// <summary>
    /// Codifica um array de bytes para Base32
    /// </summary>
    private static string Base32Encode(byte[] data)
    {
        // RFC 4648/3548
        const string base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        // Converter para Base32
        StringBuilder result = new StringBuilder((data.Length * 8 + 4) / 5);
        int buffer = 0;
        int bufferSize = 0;

        foreach (byte b in data)
        {
            buffer = (buffer << 8) | b;
            bufferSize += 8;
            while (bufferSize >= 5)
            {
                bufferSize -= 5;
                result.Append(base32Chars[(buffer >> bufferSize) & 31]);
            }
        }

        if (bufferSize > 0)
        {
            buffer = buffer << (5 - bufferSize);
            result.Append(base32Chars[buffer & 31]);
        }

        return result.ToString();
    }
}
