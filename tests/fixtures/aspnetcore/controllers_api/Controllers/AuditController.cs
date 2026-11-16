using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Shop.Controllers;

[ApiController]
[Route("audit")]
[Authorize(Policy = "Audit")]
public class AuditController : ControllerBase
{
    [HttpGet]
    public IActionResult Log() => Ok();
}
