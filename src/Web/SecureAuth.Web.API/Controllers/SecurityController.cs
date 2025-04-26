using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecureAuth.Core.Application.DTOs;
using SecureAuth.Core.Application.Interfaces;

namespace SecureAuth.Web.API.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "Admin")]
public class SecurityController : ControllerBase
{
    private readonly ISecurityAuditService _securityAuditService;
    private readonly IAuthService _authService;

    public SecurityController(
        ISecurityAuditService securityAuditService,
        IAuthService authService)
    {
        _securityAuditService = securityAuditService;
        _authService = authService;
    }

    [HttpGet("audit/logs")]
    public async Task<ActionResult<IEnumerable<SecurityLogDto>>> GetAllLogs(
        [FromQuery] DateTime? startDate, 
        [FromQuery] DateTime? endDate)
    {
        if (!startDate.HasValue)
            startDate = DateTime.UtcNow.AddDays(-7);
        
        if (!endDate.HasValue)
            endDate = DateTime.UtcNow;

        var logs = await _securityAuditService.GetByDateRangeAsync(startDate.Value, endDate.Value);
        return Ok(logs);
    }

    [HttpGet("audit/logs/type/{eventType}")]
    public async Task<ActionResult<IEnumerable<SecurityLogDto>>> GetLogsByType(string eventType)
    {
        var logs = await _securityAuditService.GetByEventTypeAsync(eventType);
        return Ok(logs);
    }

    [HttpGet("audit/logs/ip/{ipAddress}")]
    public async Task<ActionResult<IEnumerable<SecurityLogDto>>> GetLogsByIp(string ipAddress)
    {
        var logs = await _securityAuditService.GetByIpAddressAsync(ipAddress);
        return Ok(logs);
    }

    [HttpGet("audit/logs/failed-logins")]
    public async Task<ActionResult<IEnumerable<SecurityLogDto>>> GetFailedLoginAttempts()
    {
        var logs = await _securityAuditService.GetFailedLoginAttemptsAsync();
        return Ok(logs);
    }

    [HttpGet("audit/statistics")]
    public async Task<ActionResult<IEnumerable<SecurityStatisticsDto>>> GetStatistics(
        [FromQuery] DateTime? startDate, 
        [FromQuery] DateTime? endDate)
    {
        var statistics = await _securityAuditService.GetSecurityStatisticsAsync(startDate, endDate);
        return Ok(statistics);
    }

    [HttpPost("users/{id}/lock")]
    public async Task<IActionResult> LockUser(string id)
    {
        var result = await _authService.LockAccountAsync(id);
        if (!result)
            return BadRequest(new { message = "Falha ao bloquear usuário" });

        return Ok(new { message = "Usuário bloqueado com sucesso" });
    }

    [HttpPost("users/{id}/unlock")]
    public async Task<IActionResult> UnlockUser(string id)
    {
        var result = await _authService.UnlockAccountAsync(id);
        if (!result)
            return BadRequest(new { message = "Falha ao desbloquear usuário" });

        return Ok(new { message = "Usuário desbloqueado com sucesso" });
    }

    [HttpPost("audit/check-bruteforce")]
    public async Task<IActionResult> CheckBruteForce([FromBody] BruteForceCheckDto model)
    {
        var result = await _securityAuditService.CheckForBruteForceAttackAsync(
            model.UserId, model.IpAddress);

        return Ok(new { bruteForceDetected = result });
    }
}

// DTO para verificação de força bruta
public class BruteForceCheckDto
{
    public string UserId { get; set; }
    public string IpAddress { get; set; }
}
