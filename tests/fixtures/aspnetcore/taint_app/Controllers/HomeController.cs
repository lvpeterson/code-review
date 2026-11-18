using Microsoft.AspNetCore.Mvc;
using TaintApp.Models;

namespace TaintApp.Controllers;

public class HomeController : Controller
{
    public IActionResult Index(string name)
    {
        ViewBag.Name = name;
        return View();
    }

    public IActionResult Profile(string bio) => View(new ProfileVm { Bio = bio });

    public IActionResult Static() => View("Profile", new ProfileVm { Bio = "fixed" });
}
