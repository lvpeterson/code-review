using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Shop.Controllers;

[ApiController]
[Route("reports")]
[Authorize(Policy = "Missing")]
public class ReportsController : ControllerBase
{
    [HttpGet]
    public IActionResult List() => Ok();
}
