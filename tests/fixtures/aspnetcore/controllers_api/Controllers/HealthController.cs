using Microsoft.AspNetCore.Mvc;

namespace Shop.Controllers;

[Route("health")]
public class HealthController : ControllerBase
{
    [HttpGet]
    public IActionResult Get() => Ok("ok");
}
