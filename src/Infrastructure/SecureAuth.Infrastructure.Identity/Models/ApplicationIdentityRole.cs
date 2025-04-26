using Microsoft.AspNetCore.Identity;

namespace SecureAuth.Infrastructure.Identity.Models;

/// <summary>
/// Extensão do modelo de role/papel do Identity
/// </summary>
public class ApplicationIdentityRole : IdentityRole
{
    public string Description { get; set; }
}
