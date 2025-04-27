namespace SecureAuth.Core.Application.DTOs;

/// <summary>
/// DTO com o resultado das operações de autenticação
/// </summary>
public class AuthResult
{
    public bool Succeeded { get; set; }
    public string Message { get; set; } = string.Empty;
    public TokenResponseDto? Token { get; set; }
    public UserDto? User { get; set; }
    public bool RequiresTwoFactor { get; set; }
    public bool IsLockedOut { get; set; }
    public bool RequiresEmailConfirmation { get; set; }

    public static AuthResult Success(string message, TokenResponseDto? token = null, UserDto? user = null)
    {
        return new AuthResult
        {
            Succeeded = true,
            Message = message,
            Token = token,
            User = user,
            RequiresTwoFactor = false,
            IsLockedOut = false,
            RequiresEmailConfirmation = false
        };
    }

    public static AuthResult Failed(string message)
    {
        return new AuthResult
        {
            Succeeded = false,
            Message = message,
            RequiresTwoFactor = false,
            IsLockedOut = false,
            RequiresEmailConfirmation = false
        };
    }

    public static AuthResult TwoFactorRequired(string message, UserDto? user)
    {
        return new AuthResult
        {
            Succeeded = false,
            Message = message,
            User = user,
            RequiresTwoFactor = true,
            IsLockedOut = false,
            RequiresEmailConfirmation = false
        };
    }

    public static AuthResult LockedOut(string message)
    {
        return new AuthResult
        {
            Succeeded = false,
            Message = message,
            RequiresTwoFactor = false,
            IsLockedOut = true,
            RequiresEmailConfirmation = false
        };
    }

    public static AuthResult EmailConfirmationRequired(string message)
    {
        return new AuthResult
        {
            Succeeded = false,
            Message = message,
            RequiresTwoFactor = false,
            IsLockedOut = false,
            RequiresEmailConfirmation = true
        };
    }
}
