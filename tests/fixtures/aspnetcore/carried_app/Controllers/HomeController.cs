using Microsoft.AspNetCore.Mvc;
using CarriedApp.Crypto;
using CarriedApp.Deser;

namespace CarriedApp.Controllers;

public class HomeController : Controller
{
    public IActionResult Index() => View();

    [HttpPost]
    public IActionResult Hash(string password)
    {
        var digest = new WeakCrypto().HashPassword(password);
        return Content(digest);
    }

    [HttpPost]
    public IActionResult Load(string payload)
    {
        return Content(new UnsafeDeser().Parse(payload));
    }
}
