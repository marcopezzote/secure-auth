using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using QRCoder;
using OtpNet;
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
        var user = await _userRepository.GetByIdAsync(userId);
        if (user == null)
        {
            throw new ArgumentException("Usuário não encontrado", nameof(userId));
        }

        if (string.IsNullOrEmpty(user.MfaSecretKey))
        {
            user.MfaSecretKey = GenerateRandomSecretKey();
            await _userRepository.UpdateAsync(user);
        }

        issuer = string.IsNullOrEmpty(issuer) ? _mfaSettings.Issuer : issuer;
        var label = Uri.EscapeDataString(user.Email);
        var secret = user.MfaSecretKey;
        var otpauth = $"otpauth://totp/{issuer}:{label}?secret={secret}&issuer={issuer}&digits=6";

        string qrCodeBase64 = string.Empty;
        using (var qrGenerator = new QRCodeGenerator())
        {
            var qrCodeData = qrGenerator.CreateQrCode(otpauth, QRCodeGenerator.ECCLevel.Q);
            var pngQrCode = new PngByteQRCode(qrCodeData);
            var qrCodeBytes = pngQrCode.GetGraphic(20);
            qrCodeBase64 = Convert.ToBase64String(qrCodeBytes);
        }

        return new MfaSetupDto
        {
            SecretKey = user.MfaSecretKey,
            QrCodeBase64 = qrCodeBase64,
            ManualEntryKey = secret
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

        var totp = new Totp(Base32Encoding.ToBytes(user.MfaSecretKey));
        return totp.VerifyTotp(code, out _, new VerificationWindow(2, 2));
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
        return await _userRepository.SetMfaEnabledAsync(userId, true, secretKey: null);
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
        return await _userRepository.SetMfaEnabledAsync(userId, false, string.Empty);
    }

    /// <summary>
    /// Verifica se um usuário tem MFA habilitado
    /// </summary>
    public async Task<bool> IsMfaEnabledAsync(string userId)
    {
        return await _userRepository.IsMfaEnabledAsync(userId);
    }

    /// <summary>
    /// Define diretamente se MFA está habilitado para um usuário
    /// </summary>
    public async Task<bool> SetMfaEnabledAsync(string userId, bool enabled)
    {
        var user = await _userRepository.GetByIdAsync(userId);
        if (user == null)
        {
            return false;
        }

        if (enabled && string.IsNullOrEmpty(user.MfaSecretKey))
        {
            // Não podemos habilitar MFA sem uma chave secreta
            return false;
        }

        return await _userRepository.SetMfaEnabledAsync(userId, enabled, null);
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

// Adicionar classe Base32Encoding se não existir
internal static class Base32Encoding
{
    private const string Base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    public static byte[] ToBytes(string input)
    {
        input = input.TrimEnd('=');
        int byteCount = input.Length * 5 / 8;
        byte[] returnArray = new byte[byteCount];
        byte curByte = 0, bitsRemaining = 8;
        int mask = 0, arrayIndex = 0;
        foreach (char c in input)
        {
            int cValue = Base32Chars.IndexOf(char.ToUpperInvariant(c));
            if (cValue < 0) throw new ArgumentException("Invalid Base32 character", nameof(input));
            if (bitsRemaining > 5)
            {
                mask = cValue << (bitsRemaining - 5);
                curByte |= (byte)mask;
                bitsRemaining -= 5;
            }
            else
            {
                mask = cValue >> (5 - bitsRemaining);
                curByte |= (byte)mask;
                returnArray[arrayIndex++] = curByte;
                curByte = (byte)(cValue << (3 + bitsRemaining));
                bitsRemaining += 3;
            }
        }
        if (arrayIndex != byteCount)
        {
            returnArray[arrayIndex] = curByte;
        }
        return returnArray;
    }
}
