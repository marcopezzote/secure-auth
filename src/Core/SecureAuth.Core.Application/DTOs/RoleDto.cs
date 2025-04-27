namespace SecureAuth.Core.Application.DTOs;

/// <summary>
/// DTO para papel/função
/// </summary>
public class RoleDto
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
}
