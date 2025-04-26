using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecureAuth.Core.Application.DTOs;
using SecureAuth.Core.Application.Interfaces;

namespace SecureAuth.Web.API.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
public class UsersController : ControllerBase
{
    private readonly IUserService _userService;

    public UsersController(IUserService userService)
    {
        _userService = userService;
    }

    [HttpGet]
    [Authorize(Roles = "Admin")]
    public async Task<ActionResult<IEnumerable<UserDto>>> GetAll()
    {
        var users = await _userService.GetAllAsync();
        return Ok(users);
    }

    [HttpGet("{id}")]
    public async Task<ActionResult<UserDto>> GetById(string id)
    {
        // Verificar se o usuário está acessando seus próprios dados ou é um admin
        var currentUserId = User.FindFirst("sub")?.Value;
        var isAdmin = User.IsInRole("Admin");

        if (currentUserId != id && !isAdmin)
            return Forbid();

        var user = await _userService.GetByIdAsync(id);
        if (user == null)
            return NotFound();

        return Ok(user);
    }

    [HttpGet("email/{email}")]
    [Authorize(Roles = "Admin")]
    public async Task<ActionResult<UserDto>> GetByEmail(string email)
    {
        var user = await _userService.GetByEmailAsync(email);
        if (user == null)
            return NotFound();

        return Ok(user);
    }

    [HttpPut("{id}")]
    public async Task<IActionResult> Update(string id, [FromBody] UserDto userDto)
    {
        // Verificar se o usuário está atualizando seus próprios dados ou é um admin
        var currentUserId = User.FindFirst("sub")?.Value;
        var isAdmin = User.IsInRole("Admin");

        if (currentUserId != id && !isAdmin)
            return Forbid();

        if (id != userDto.Id)
            return BadRequest();

        var result = await _userService.UpdateUserAsync(userDto);
        if (!result)
            return BadRequest();

        return NoContent();
    }

    [HttpDelete("{id}")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> Delete(string id)
    {
        var result = await _userService.DeleteUserAsync(id);
        if (!result)
            return NotFound();

        return NoContent();
    }

    [HttpGet("{id}/roles")]
    public async Task<ActionResult<IEnumerable<string>>> GetUserRoles(string id)
    {
        // Verificar se o usuário está acessando seus próprios dados ou é um admin
        var currentUserId = User.FindFirst("sub")?.Value;
        var isAdmin = User.IsInRole("Admin");

        if (currentUserId != id && !isAdmin)
            return Forbid();

        var roles = await _userService.GetUserRolesAsync(id);
        return Ok(roles);
    }

    [HttpPost("{id}/roles")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> AssignRole(string id, [FromBody] AssignRoleDto model)
    {
        var result = await _userService.AssignRoleAsync(id, model.RoleName);
        if (!result)
            return BadRequest();

        return Ok();
    }

    [HttpDelete("{id}/roles/{roleName}")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> RemoveRole(string id, string roleName)
    {
        var result = await _userService.RemoveRoleAsync(id, roleName);
        if (!result)
            return BadRequest();

        return Ok();
    }

    [HttpGet("{id}/security-logs")]
    public async Task<ActionResult<IEnumerable<SecurityLogDto>>> GetUserSecurityLogs(string id)
    {
        // Verificar se o usuário está acessando seus próprios dados ou é um admin
        var currentUserId = User.FindFirst("sub")?.Value;
        var isAdmin = User.IsInRole("Admin");

        if (currentUserId != id && !isAdmin)
            return Forbid();

        var logs = await _userService.GetUserSecurityLogsAsync(id);
        return Ok(logs);
    }
}

// DTO para atribuição de papéis
public class AssignRoleDto
{
    public string RoleName { get; set; }
}
