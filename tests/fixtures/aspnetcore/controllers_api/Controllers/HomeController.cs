using Microsoft.AspNetCore.Mvc;

namespace Shop.Controllers;

public class HomeController : Controller
{
    public IActionResult Index() => View();

    [HttpPost]
    public IActionResult Save() => RedirectToAction("Index");
}
