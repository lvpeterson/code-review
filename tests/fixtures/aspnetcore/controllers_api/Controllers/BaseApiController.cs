using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Shop.Controllers;

[ApiController]
[Authorize]
public abstract class BaseApiController : ControllerBase
{
}
