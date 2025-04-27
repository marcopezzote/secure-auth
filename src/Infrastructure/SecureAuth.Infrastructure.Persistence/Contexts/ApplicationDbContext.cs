using Microsoft.EntityFrameworkCore;
using SecureAuth.Infrastructure.Persistence.Models;

namespace SecureAuth.Infrastructure.Persistence.Contexts;

/// <summary>
/// Contexto do Entity Framework para a aplicação
/// </summary>
public class ApplicationDbContext : DbContext
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    public DbSet<RefreshToken> RefreshTokens { get; set; }
    public DbSet<SecurityAuditLog> SecurityAuditLogs { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Configuração da entidade RefreshToken
        modelBuilder.Entity<RefreshToken>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Token).IsRequired().HasMaxLength(128);
            entity.Property(e => e.UserId).IsRequired().HasMaxLength(450);
            entity.Property(e => e.ExpiryDate).IsRequired();
            entity.Property(e => e.Created).IsRequired();
            entity.Property(e => e.CreatedByIp).HasMaxLength(50);
            entity.Property(e => e.RevokedByIp).HasMaxLength(50);
            entity.Property(e => e.ReplacedByToken).HasMaxLength(128);
            entity.Property(e => e.ReasonRevoked).HasMaxLength(256);
        });

        // Configuração da entidade SecurityAuditLog
        modelBuilder.Entity<SecurityAuditLog>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Timestamp).IsRequired();
            entity.Property(e => e.EventType).IsRequired();
            entity.Property(e => e.IpAddress).HasMaxLength(50);
            entity.Property(e => e.UserAgent).HasMaxLength(512);
            entity.Property(e => e.UserId).HasMaxLength(450);
            entity.Property(e => e.IsSuccess).IsRequired();
            entity.Property(e => e.AdditionalInfo).HasMaxLength(1024);
        });
    }
}
