using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SecureAuth.Core.Application.Interfaces;
using SecureAuth.Core.Application.Services;
using SecureAuth.Core.Application.Settings;
using SecureAuth.Core.Domain.Interfaces;
using SecureAuth.Infrastructure.Identity.Contexts;
using SecureAuth.Infrastructure.Identity.Models;
using SecureAuth.Infrastructure.Identity.Repositories;
using SecureAuth.Infrastructure.Identity.Services;
using SecureAuth.Infrastructure.Persistence.Contexts;
using SecureAuth.Infrastructure.Persistence.Repositories;

namespace SecureAuth.Infrastructure.Identity;

/// <summary>
/// Responsável por configurar e registrar serviços da camada de infraestrutura
/// </summary>
public static class DependencyInjection
{
    public static IServiceCollection AddInfrastructureServices(this IServiceCollection services, IConfiguration configuration)
    {
        // Configurar dbContext do Identity
        services.AddDbContext<ApplicationIdentityDbContext>(options =>
            options.UseSqlServer(
                configuration.GetConnectionString("IdentityConnection"),
                b => b.MigrationsAssembly(typeof(ApplicationIdentityDbContext).Assembly.FullName)));

        // Configurar dbContext da aplicação
        services.AddDbContext<ApplicationDbContext>(options =>
            options.UseSqlServer(
                configuration.GetConnectionString("DefaultConnection"),
                b => b.MigrationsAssembly(typeof(ApplicationDbContext).Assembly.FullName)));

        // Configurar Identity
        services.AddIdentity<ApplicationIdentityUser, ApplicationIdentityRole>(options =>
            {
                // Configurações de senha
                options.Password.RequiredLength = 8;
                options.Password.RequireDigit = true;
                options.Password.RequireLowercase = true;
                options.Password.RequireUppercase = true;
                options.Password.RequireNonAlphanumeric = true;

                // Configurações de bloqueio
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.AllowedForNewUsers = true;

                // Configurações de usuário
                options.User.RequireUniqueEmail = true;
                options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";

                // Configurações de confirmação de email
                options.SignIn.RequireConfirmedEmail = true;
                options.SignIn.RequireConfirmedAccount = true;
            })
            .AddEntityFrameworkStores<ApplicationIdentityDbContext>()
            .AddDefaultTokenProviders();

        // Configurar JWT
        services.Configure<JwtSettings>(configuration.GetSection("JwtSettings"));

        // Configurar MFA
        services.Configure<MfaSettings>(configuration.GetSection("MfaSettings"));

        // Configurar Email
        services.Configure<EmailSettings>(configuration.GetSection("EmailSettings"));

        // Registrar repositórios
        services.AddScoped<IUserRepository, UserRepository>(); // <-- LINHA ADICIONADA PARA CORREÇÃO
        services.AddScoped<SecureAuth.Infrastructure.Persistence.Interfaces.IRefreshTokenRepository, RefreshTokenRepository>();
        services.AddScoped<SecureAuth.Infrastructure.Persistence.Interfaces.ISecurityAuditRepository, SecurityAuditRepository>();

        // Registrar serviços
        services.AddScoped<IJwtService, JwtService>();
        services.AddScoped<IMfaService, MfaService>();
        services.AddScoped<IEmailService, EmailService>();
        services.AddScoped<ISecurityAuditService, SecurityAuditService>();
        services.AddScoped<IUserService, UserService>();
        services.AddScoped<IRoleService, RoleService>();

        // Registrar serviço de autenticação
        // Primeiro registramos a implementação base como um serviço nomeado
        services.AddScoped<AuthService>();
        // Depois registramos a implementação da infraestrutura como a implementação padrão da interface
        services.AddScoped<IAuthService>(provider =>
            new AuthServiceInfrastructure(
                provider.GetRequiredService<AuthService>(),
                provider.GetRequiredService<IMfaService>(),
                provider.GetRequiredService<ILogger<AuthServiceInfrastructure>>()
            )
        );

        return services;
    }
}