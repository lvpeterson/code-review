using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Shop.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class OrdersController : ControllerBase
{
    [HttpGet("{id:int}")]
    public IActionResult Get(int id) => Ok(id);

    [HttpDelete("{id}")]
    [Authorize(Policy = "Admin")]
    public IActionResult Delete(int id) => NoContent();

    [HttpGet("public")]
    [AllowAnonymous]
    public IActionResult Public() => Ok();

    [HttpGet("~/legacy/orders")]
    public IActionResult Legacy() => Ok();

    [NonAction]
    public void Helper() { }
}
