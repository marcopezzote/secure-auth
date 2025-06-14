using SecureAuth.Infrastructure.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Adicionar serviços ao contêiner
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddInfrastructureServices(builder.Configuration);

var app = builder.Build();

// Configurar o pipeline HTTP
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthorization();
app.MapControllers();

// Garante que as migrations sejam aplicadas na inicialização
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    try
    {
        // Migration para o banco de dados do Identity
        var identityContext = services.GetRequiredService<SecureAuth.Infrastructure.Identity.Contexts.ApplicationIdentityDbContext>();
        identityContext.Database.Migrate();

        // Migration para o banco de dados da Aplicação
        var appContext = services.GetRequiredService<SecureAuth.Infrastructure.Persistence.Contexts.ApplicationDbContext>();
        appContext.Database.Migrate();
    }
    catch (Exception ex)
    {
        var logger = services.GetRequiredService<ILogger<Program>>();
        logger.LogError(ex, "Ocorreu um erro ao aplicar as migrations na inicialização.");
    }
}

app.Run();


public partial class Program { }
