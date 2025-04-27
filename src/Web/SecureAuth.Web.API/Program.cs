using Microsoft.AspNetCore.Mvc;
using SecureAuth.Core.Application.DTOs;
using SecureAuth.Core.Application.Interfaces;
using SecureAuth.Infrastructure.Identity;
using SecureAuth.Web.API.Extensions;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();

// Adicionar serviços de infraestrutura
builder.Services.AddInfrastructureServices(builder.Configuration);

// Configurar autenticação JWT
builder.Services.AddJwtAuthentication(builder.Configuration);

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    // Configurar Swagger para autenticação JWT
    c.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\"",
        Name = "Authorization",
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    c.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
    {
        {
            new Microsoft.OpenApi.Models.OpenApiSecurityScheme
            {
                Reference = new Microsoft.OpenApi.Models.OpenApiReference
                {
                    Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[] {}
        }
    });
});

// Configurar CORS
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowSpecificOrigins",
        builder => builder
            .WithOrigins("http://localhost:3000") // Adicione aqui as origens permitidas
            .AllowAnyMethod()
            .AllowAnyHeader()
            .AllowCredentials());
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseCors("AllowSpecificOrigins");
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

// Configurar endpoints de autenticação via Minimal API
app.MapPost("/api/auth/register", async ([FromBody] UserRegistrationDto model, [FromServices] IAuthService authService, HttpContext context) =>
{
    var origin = $"{context.Request.Scheme}://{context.Request.Host}";
    var result = await authService.RegisterUserAsync(model, origin);
    
    if (result.Succeeded)
        return Results.Ok(new { message = result.Message });
    
    return Results.BadRequest(new { message = result.Message });
});

app.MapPost("/api/auth/login", async ([FromBody] LoginDto model, [FromServices] IAuthService authService, HttpContext context) =>
{
    var ipAddress = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    var userAgent = context.Request.Headers.UserAgent.ToString();
    
    var result = await authService.LoginAsync(model, ipAddress, userAgent);
    
    if (result.Succeeded)
        return Results.Ok(new { token = result.Token, user = result.User });
    
    if (result.RequiresTwoFactor)
        return Results.Ok(new { requiresTwoFactor = true, user = result.User });
    
    if (result.IsLockedOut)
        return Results.Json(new { message = result.Message, isLockedOut = true }, statusCode: StatusCodes.Status401Unauthorized);
    
    if (result.RequiresEmailConfirmation)
        return Results.Json(new { message = result.Message, requiresEmailConfirmation = true }, statusCode: StatusCodes.Status401Unauthorized);
    
    return Results.Json(new { message = result.Message }, statusCode: StatusCodes.Status401Unauthorized);
});

app.MapPost("/api/auth/refresh-token", async ([FromBody] RefreshTokenDto model, [FromServices] IAuthService authService, HttpContext context) =>
{
    var ipAddress = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    var result = await authService.RefreshTokenAsync(model.RefreshToken, ipAddress);
    
    if (result.Succeeded)
        return Results.Ok(new { token = result.Token, user = result.User });
    
    return Results.Json(new { message = result.Message }, statusCode: StatusCodes.Status401Unauthorized);
});

app.MapPost("/api/auth/revoke-token", async ([FromBody] RefreshTokenDto model, [FromServices] IAuthService authService, HttpContext context) =>
{
    var ipAddress = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    var result = await authService.RevokeTokenAsync(model.RefreshToken, ipAddress);
    
    if (result)
        return Results.Ok(new { message = "Token revogado com sucesso" });
    
    return Results.BadRequest(new { message = "Token inválido" });
});

app.MapGet("/api/auth/confirm-email", async ([FromQuery] string userId, [FromQuery] string token, [FromServices] IAuthService authService) =>
{
    var result = await authService.ConfirmEmailAsync(userId, token);
    
    if (result)
        return Results.Ok(new { message = "E-mail confirmado com sucesso" });
    
    return Results.BadRequest(new { message = "Falha ao confirmar e-mail. O link pode estar expirado ou ser inválido." });
});

app.MapPost("/api/auth/forgot-password", async ([FromBody] ForgotPasswordDto model, [FromServices] IAuthService authService, HttpContext context) =>
{
    var origin = $"{context.Request.Scheme}://{context.Request.Host}";
    var result = await authService.ForgotPasswordAsync(model.Email, origin);
    
    // Sempre retornamos sucesso para evitar vazamento de informação sobre existência do e-mail
    return Results.Ok(new { message = "Se o e-mail existir em nossa base, você receberá instruções para redefinir sua senha." });
});

app.MapPost("/api/auth/reset-password", async ([FromBody] ResetPasswordDto model, [FromServices] IAuthService authService) =>
{
    var result = await authService.ResetPasswordAsync(model);
    
    if (result)
        return Results.Ok(new { message = "Senha redefinida com sucesso" });
    
    return Results.BadRequest(new { message = "Falha ao redefinir senha. O link pode estar expirado ou ser inválido." });
});

// Endpoints para gerenciamento de MFA
app.MapGet("/api/auth/mfa/setup", async ([FromServices] IAuthService authService, HttpContext context) =>
{
    var userId = context.User.FindFirst("sub")?.Value;
    if (string.IsNullOrEmpty(userId))
        return Results.Unauthorized();
    
    var issuer = "SecureAuth";
    var result = await authService.SetupMfaAsync(userId, issuer);
    
    return Results.Ok(result);
}).RequireAuthorization();

app.MapPost("/api/auth/mfa/enable", async ([FromBody] MfaVerifyDto model, [FromServices] IAuthService authService, HttpContext context) =>
{
    var userId = context.User.FindFirst("sub")?.Value;
    if (string.IsNullOrEmpty(userId))
        return Results.Unauthorized();
    
    var result = await authService.VerifyMfaTokenAsync(userId, model.Code);
    if (!result)
        return Results.BadRequest(new { message = "Código inválido" });
    
    var enableResult = await authService.SetMfaEnabledAsync(userId, true);
    if (enableResult)
        return Results.Ok(new { message = "MFA habilitado com sucesso" });
    
    return Results.BadRequest(new { message = "Falha ao habilitar MFA" });
}).RequireAuthorization();

app.MapPost("/api/auth/mfa/disable", async ([FromBody] MfaVerifyDto model, [FromServices] IAuthService authService, HttpContext context) =>
{
    var userId = context.User.FindFirst("sub")?.Value;
    if (string.IsNullOrEmpty(userId))
        return Results.Unauthorized();
    
    var result = await authService.DisableMfaAsync(userId, model.Code);
    if (result)
        return Results.Ok(new { message = "MFA desabilitado com sucesso" });
    
    return Results.BadRequest(new { message = "Código inválido ou falha ao desabilitar MFA" });
}).RequireAuthorization();

app.MapGet("/api/auth/mfa/status", async ([FromServices] IAuthService authService, HttpContext context) =>
{
    var userId = context.User.FindFirst("sub")?.Value;
    if (string.IsNullOrEmpty(userId))
        return Results.Unauthorized();
    
    var isEnabled = await authService.IsMfaEnabledAsync(userId);
    return Results.Ok(new { isEnabled });
}).RequireAuthorization();

app.Run();

// Adicionar classes DTO necessárias
public class RefreshTokenDto
{
    public string RefreshToken { get; set; } = string.Empty;
}

public class ForgotPasswordDto
{
    public string Email { get; set; } = string.Empty;
}

public class MfaVerifyDto
{
    public string Code { get; set; } = string.Empty;
}
