using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using SecureAuth.Infrastructure.Identity.Models;

namespace SecureAuth.Infrastructure.Identity.Contexts;

/// <summary>
/// Contexto do Entity Framework para o Identity
/// </summary>
public class ApplicationIdentityDbContext : IdentityDbContext<ApplicationIdentityUser, ApplicationIdentityRole, string>
{
    public ApplicationIdentityDbContext(DbContextOptions<ApplicationIdentityDbContext> options)
        : base(options)
    {
    }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        // Configurações adicionais do modelo
        builder.Entity<ApplicationIdentityUser>()
            .Property(u => u.MfaSecretKey)
            .HasMaxLength(256);

        builder.Entity<ApplicationIdentityUser>()
            .Property(u => u.IsMfaEnabled)
            .HasDefaultValue(false);
            
        builder.Entity<ApplicationIdentityUser>()
            .Property(u => u.CreatedAt)
            .IsRequired();

        builder.Entity<ApplicationIdentityRole>()
            .Property(r => r.Description)
            .HasMaxLength(256);
    }
}
