# 🔐 SecureAuth

<div align="center">
  <img src="https://img.shields.io/badge/.NET-8.0-512BD4?style=for-the-badge&logo=dotnet&logoColor=white" alt=".NET 8.0" />
  <img src="https://img.shields.io/badge/C%23-239120?style=for-the-badge&logo=c-sharp&logoColor=white" alt="C#" />
  <img src="https://img.shields.io/badge/EF%20Core-8.0-purple?style=for-the-badge&logo=.net&logoColor=white" alt="Entity Framework Core" />
  <img src="https://img.shields.io/badge/JWT-Authentication-000000?style=for-the-badge&logo=json-web-tokens&logoColor=white" alt="JWT" />
  <img src="https://img.shields.io/badge/Clean%20Architecture-0078D7?style=for-the-badge&logo=architecture&logoColor=white" alt="Clean Architecture" />
</div>

## 📋 Visão Geral

**SecureAuth** é uma solução de autenticação e autorização robusta e escalável desenvolvida em ASP.NET Core 8. O projeto implementa as melhores práticas de segurança para aplicações modernas, incluindo autenticação multi-fator, gestão avançada de tokens JWT, mecanismos de proteção contra ataques de força bruta e um sistema detalhado de auditoria de segurança.

Desenvolvido com foco em segurança, escalabilidade e manutenibilidade, o SecureAuth fornece uma base sólida para aplicações empresariais que necessitam de um sistema de identidade completo e seguro.

### 🔒 Diferenciais de Segurança

- **Proteção Contra Ataques Comuns**: Implementação robusta contra SQL Injection, XSS, CSRF e ataques de força bruta
- **Tokens Seguros**: Tokens JWT com assinatura e criptografia, curto tempo de expiração e refresh tokens rotativos
- **Armazenamento Seguro**: Senhas armazenadas com hashing avançado (PBKDF2) e salt único por usuário
- **Logs Detalhados**: Registro completo de tentativas de login, alterações de perfil e eventos de segurança
- **Conformidade com Padrões**: Implementação seguindo recomendações OWASP e práticas modernas de segurança

## 🚀 Funcionalidades Principais

- ✅ **Autenticação Completa**: Registro, login e gestão de usuários
- 🔑 **Multi-Factor Authentication (MFA)**: Autenticação de dois fatores integrada
- 🔄 **Gestão Avançada de Tokens**: JWT com refresh tokens e revogação
- 🔒 **Políticas de Senha Robustas**: Configuração flexível de regras de senha
- 📧 **Verificação por E-mail**: Confirmação de conta e redefinição segura de senha
- 🛡️ **Proteção Contra Ataques**: Bloqueio automático de contas e rate limiting
- 📊 **Auditoria de Segurança**: Registro detalhado de eventos e tentativas de acesso
- 👥 **Role-Based Access Control (RBAC)**: Gerenciamento avançado de permissões
- 📝 **Logging Extensivo**: Monitoramento detalhado de atividades de segurança

## 🏗️ Arquitetura

O projeto implementa princípios de **Clean Architecture** para garantir escalabilidade, testabilidade e manutenibilidade:

```
SecureAuth/
├── src/
│   ├── Core/
│   │   ├── Domain/      # Entidades e regras de negócio
│   │   └── Application/ # Casos de uso, DTOs e interfaces
│   ├── Infrastructure/
│   │   ├── Identity/    # Implementação de Identity e autenticação
│   │   └── Persistence/ # Implementação de persistência de dados
│   └── Web/
│       └── API/         # Interface REST para comunicação externa
└── tests/
    ├── UnitTests/       # Testes de componentes isolados
    └── IntegrationTests/ # Testes de integração entre componentes
```

## 🧠 Padrões e Tecnologias

### 🔧 Tecnologias Core
- **ASP.NET Core 8**: Framework web moderno e de alto desempenho 
- **C# 12**: Linguagem de programação fortemente tipada e orientada a objetos
- **Entity Framework Core 8**: ORM para acesso a dados com suporte a migrations
- **ASP.NET Identity**: Framework completo para autenticação e autorização
- **SQL Server**: Sistema de gerenciamento de banco de dados relacional

### 🔐 Segurança e Autenticação
- **JWT Authentication**: Autenticação stateless com tokens seguros
- **TOTP MFA**: Autenticação de dois fatores baseada em tempo (compatível com Google Authenticator)
- **Rate Limiting**: Limitação de requisições para prevenção de ataques de força bruta
- **Anti-Forgery Protection**: Proteção contra ataques CSRF

### 🏛️ Arquitetura e Padrões
- **Clean Architecture**: Separação de responsabilidades e inversão de dependências
- **CQRS Pattern**: Segregação de responsabilidades entre comandos e consultas
- **Repository Pattern**: Abstração da camada de acesso a dados
- **SOLID Principles**: Princípios de design para código limpo e manutenível
- **Dependency Injection**: Baixo acoplamento e alta testabilidade

### 🧪 Testes e Qualidade
- **XUnit**: Framework moderno para testes unitários e de integração
- **Moq**: Framework de mocking para testes isolados
- **Fluent Validations**: Validações de entrada robustas e expressivas 
- **StyleCop**: Análise estática para garantir consistência de código

## 🛠️ Requisitos

- [.NET SDK 8.0](https://dotnet.microsoft.com/download) ou superior
- [SQL Server](https://www.microsoft.com/sql-server/) (ou outra base de dados compatível com EF Core)
- [Visual Studio 2022](https://visualstudio.microsoft.com/) / [Visual Studio Code](https://code.visualstudio.com/) / [JetBrains Rider](https://www.jetbrains.com/rider/)

## ⚙️ Configuração e Execução

1. Clone o repositório:
   ```bash
   git clone https://github.com/marcopezzote/secure-auth.git
   cd secure-auth
   ```

2. Restaure os pacotes NuGet:
   ```bash
   dotnet restore
   ```

3. Configure as conexões de banco de dados em `appsettings.json`:
   ```json
   "ConnectionStrings": {
     "DefaultConnection": "Server=(localdb)\\mssqllocaldb;Database=SecureAuth;Trusted_Connection=True;MultipleActiveResultSets=true",
     "IdentityConnection": "Server=(localdb)\\mssqllocaldb;Database=SecureAuthIdentity;Trusted_Connection=True;MultipleActiveResultSets=true"
   }
   ```

4. Execute as migrações do Entity Framework:
   ```bash
   dotnet ef database update -p src/Infrastructure/SecureAuth.Infrastructure.Identity -s src/Web/SecureAuth.Web.API
   dotnet ef database update -p src/Infrastructure/SecureAuth.Infrastructure.Persistence -s src/Web/SecureAuth.Web.API
   ```

5. Execute o projeto:
   ```bash
   dotnet run --project src/Web/SecureAuth.Web.API/SecureAuth.Web.API.csproj
   ```

6. Acesse a documentação da API via Swagger:
   ```
   https://localhost:7001/swagger
   ```

## 📚 API Endpoints

### Autenticação

| Método | Endpoint | Descrição |
|--------|----------|-----------|
| POST | `/api/auth/register` | Registro de novo usuário |
| POST | `/api/auth/login` | Login de usuário |
| POST | `/api/auth/refresh-token` | Renovação de token JWT expirado |
| POST | `/api/auth/revoke-token` | Revogação de refresh token |
| GET | `/api/auth/confirm-email` | Confirmação de email |
| POST | `/api/auth/forgot-password` | Solicitação de reset de senha |
| POST | `/api/auth/reset-password` | Redefinição de senha com token |
| GET | `/api/auth/mfa/setup` | Configuração de MFA |
| POST | `/api/auth/mfa/enable` | Ativação de MFA |
| POST | `/api/auth/mfa/verify` | Verificação de código MFA |

### Usuários e Perfis

| Método | Endpoint | Descrição |
|--------|----------|-----------|
| GET | `/api/users` | Listagem de usuários |
| GET | `/api/users/{id}` | Detalhes de usuário específico |
| PUT | `/api/users/{id}` | Atualização de usuário |
| DELETE | `/api/users/{id}` | Remoção de usuário |
| GET | `/api/roles` | Listagem de perfis |
| GET | `/api/users/{id}/roles` | Perfis de um usuário |
| POST | `/api/users/{id}/roles` | Atribuição de perfil |
| DELETE | `/api/users/{id}/roles/{role}` | Remoção de perfil |

### Segurança e Auditoria

| Método | Endpoint | Descrição |
|--------|----------|-----------|
| GET | `/api/security/audit/logs` | Logs de auditoria |
| GET | `/api/security/audit/logs/type/{type}` | Logs por tipo de evento |
| GET | `/api/security/audit/logs/user/{userId}` | Logs por usuário |
| GET | `/api/security/audit/logs/ip/{ipAddress}` | Logs por endereço IP |
| GET | `/api/security/audit/statistics` | Estatísticas de segurança |
| POST | `/api/security/users/{id}/lock` | Bloqueio de conta |
| POST | `/api/security/users/{id}/unlock` | Desbloqueio de conta |

## 🧪 Testes

O projeto conta com uma suíte completa de testes unitários e de integração:

```bash
# Executar testes unitários
dotnet test tests/UnitTests/SecureAuth.UnitTests.csproj

# Executar testes de integração
dotnet test tests/IntegrationTests/SecureAuth.IntegrationTests.csproj

# Executar todos os testes com cobertura
dotnet test /p:CollectCoverage=true /p:CoverletOutputFormat=lcov
```

## 📊 Análise de Código

O projeto implementa análise estática de código para garantir qualidade e aderência às convenções:

```bash
# Executar análise com StyleCop
dotnet build /p:RunAnalyzersDuringBuild=true
```

## 📄 Licença

Este projeto está licenciado sob a licença MIT. Consulte o arquivo [LICENSE](LICENSE) para mais detalhes.

## 👨‍💻 Autor

**Marco Pezzote** - Desenvolvedor Full Stack .NET
- [LinkedIn](https://www.linkedin.com/in/marcopezzote/)
- [Website](https://marcopezzote.tech)
- [GitHub](https://github.com/marcopezzote)

---

<div align="center">
  <sub>Construído com ❤️ usando ASP.NET Core 8</sub>
</div>
