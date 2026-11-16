using Microsoft.AspNetCore.Mvc;

namespace Shop.Controllers.Admin;

[Area("Admin")]
[Route("[area]/[controller]/[action]")]
public class ManageController : Controller
{
    public IActionResult Reset() => Ok();
}
