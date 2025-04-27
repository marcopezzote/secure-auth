using System.Threading.Tasks;
using SecureAuth.Core.Application.DTOs;

namespace SecureAuth.Core.Application.Interfaces
{
    public interface IMfaService
    {
        Task<MfaSetupDto> SetupMfaAsync(string userId, string issuer);
        Task<bool> VerifyCodeAsync(string userId, string code);
        Task<bool> EnableMfaAsync(string userId, string code);
        Task<bool> DisableMfaAsync(string userId, string code);
        Task<bool> IsMfaEnabledAsync(string userId);
        Task<bool> SetMfaEnabledAsync(string userId, bool enabled);
    }
}
