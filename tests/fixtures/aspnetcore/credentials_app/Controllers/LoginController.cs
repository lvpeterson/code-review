using Microsoft.AspNetCore.Mvc;

namespace Vault.Controllers;

public class LoginRequest
{
    public string UserName { get; set; } = "";
    public string Password { get; set; } = "";
}

[ApiController]
[Route("api/login")]
public class LoginController : ControllerBase
{
    private const string AdminPassword = "Sup3rSecret!";

    [HttpPost]
    public IActionResult Post(LoginRequest request, string storedPassword)
    {
        if (request.Password == storedPassword)
        {
            return Ok();
        }
        return Unauthorized();
    }
}
