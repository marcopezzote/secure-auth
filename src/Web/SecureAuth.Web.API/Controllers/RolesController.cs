using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecureAuth.Core.Application.DTOs;
using SecureAuth.Core.Application.Interfaces;

namespace SecureAuth.Web.API.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "Admin")]
public class RolesController : ControllerBase
{
    private readonly IRoleService _roleService;

    public RolesController(IRoleService roleService)
    {
        _roleService = roleService;
    }

    [HttpGet]
    public async Task<ActionResult<IEnumerable<RoleDto>>> GetAll()
    {
        var roles = await _roleService.GetAllAsync();
        return Ok(roles);
    }

    [HttpGet("{id}")]
    public async Task<ActionResult<RoleDto>> GetById(string id)
    {
        var role = await _roleService.GetByIdAsync(id);
        if (role == null)
            return NotFound();

        return Ok(role);
    }

    [HttpGet("name/{name}")]
    public async Task<ActionResult<RoleDto>> GetByName(string name)
    {
        var role = await _roleService.GetByNameAsync(name);
        if (role == null)
            return NotFound();

        return Ok(role);
    }

    [HttpPost]
    public async Task<IActionResult> Create([FromBody] RoleDto roleDto)
    {
        var result = await _roleService.CreateAsync(roleDto);
        if (!result)
            return BadRequest();

        return CreatedAtAction(nameof(GetByName), new { name = roleDto.Name }, roleDto);
    }

    [HttpPut("{id}")]
    public async Task<IActionResult> Update(string id, [FromBody] RoleDto roleDto)
    {
        if (id != roleDto.Id)
            return BadRequest();

        var result = await _roleService.UpdateAsync(roleDto);
        if (!result)
            return BadRequest();

        return NoContent();
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> Delete(string id)
    {
        var result = await _roleService.DeleteAsync(id);
        if (!result)
            return NotFound();

        return NoContent();
    }

    [HttpGet("{roleName}/users")]
    public async Task<ActionResult<IEnumerable<UserDto>>> GetUsersInRole(string roleName)
    {
        var users = await _roleService.GetUsersInRoleAsync(roleName);
        return Ok(users);
    }
}
