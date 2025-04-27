namespace SecureAuth.Core.Domain.Entities;

/// <summary>
/// Entidade para representar um papel/função
/// Compatível com Microsoft.AspNetCore.Identity
/// </summary>
public class ApplicationRole
{
    public string Id { get; set; }
    public string Name { get; set; }
    public string NormalizedName { get; set; }
    public string ConcurrencyStamp { get; set; }
    public string Description { get; set; }
}
