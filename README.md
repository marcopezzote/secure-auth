# SecureAuth

SecureAuth é uma solução completa de autenticação e autorização segura desenvolvida em .NET Core. Este projeto implementa as melhores práticas de segurança para autenticação de usuários, incluindo autenticação de dois fatores, gerenciamento de tokens JWT, proteção contra ataques de força bruta e auditoria detalhada de eventos de segurança.

## Tecnologias e Padrões

- ASP.NET Core 8
- Entity Framework Core
- Arquitetura Limpa (Clean Architecture)
- Autenticação JWT com Refresh Tokens
- Autenticação de Dois Fatores (MFA)
- CQRS (Command Query Responsibility Segregation)
- Repository Pattern
- Unit Tests e Integration Tests

## Funcionalidades

- Registro e Login de usuários
- Confirmação de e-mail
- Autenticação de dois fatores (MFA)
- Refresh Tokens para renovação de sessão
- Bloqueio automático de contas
- Auditoria de eventos de segurança
- Gerenciamento de usuários e papéis
- Redefinição de senha segura
- Proteção contra ataques de força bruta

## Estrutura do Projeto

O projeto segue os princípios de Arquitetura Limpa (Clean Architecture):

- **SecureAuth.Core.Domain**: Entidades de domínio e interfaces de repositório
- **SecureAuth.Core.Application**: Lógica de aplicação, DTOs, interfaces e serviços
- **SecureAuth.Infrastructure.Identity**: Implementação de autenticação e identidade
- **SecureAuth.Infrastructure.Persistence**: Implementação de persistência com EF Core
- **SecureAuth.Web.API**: API REST para comunicação com clientes
- **SecureAuth.UnitTests**: Testes unitários
- **SecureAuth.IntegrationTests**: Testes de integração

## Como Executar

1. Clone o repositório
2. Configure as strings de conexão no arquivo `appsettings.json`
3. Execute as migrações do Entity Framework Core
4. Execute a aplicação

```bash
dotnet restore
dotnet ef database update
dotnet run --project src/Web/SecureAuth.Web.API/SecureAuth.Web.API.csproj
```

## API Endpoints

### Autenticação
- POST /api/auth/register - Registro de usuário
- POST /api/auth/login - Login
- POST /api/auth/refresh-token - Atualização de token
- POST /api/auth/revoke-token - Revogação de token
- GET /api/auth/confirm-email - Confirmação de e-mail
- POST /api/auth/forgot-password - Solicitação de redefinição de senha
- POST /api/auth/reset-password - Redefinição de senha

### MFA
- GET /api/auth/mfa/setup - Configuração de MFA
- POST /api/auth/mfa/enable - Habilitação de MFA
- POST /api/auth/mfa/disable - Desabilitação de MFA
- GET /api/auth/mfa/status - Status de MFA

### Usuários
- GET /api/users - Listar usuários
- GET /api/users/{id} - Obter usuário por ID
- PUT /api/users/{id} - Atualizar usuário
- DELETE /api/users/{id} - Excluir usuário
- GET /api/users/{id}/roles - Obter papéis do usuário
- POST /api/users/{id}/roles - Atribuir papel ao usuário
- DELETE /api/users/{id}/roles/{roleName} - Remover papel do usuário

### Segurança
- GET /api/security/audit/logs - Obter logs de auditoria
- GET /api/security/audit/logs/type/{eventType} - Filtrar logs por tipo
- GET /api/security/audit/logs/ip/{ipAddress} - Filtrar logs por IP
- GET /api/security/audit/statistics - Obter estatísticas de segurança
- POST /api/security/users/{id}/lock - Bloquear usuário
- POST /api/security/users/{id}/unlock - Desbloquear usuário

## Licença

Este projeto está licenciado sob a licença MIT - veja o arquivo [LICENSE](LICENSE) para mais detalhes.
