using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;

namespace ConfigApp.Controllers;

// MVC controller: CSRF-001 (POST with no antiforgery validation), CSRF-002 (explicitly ignored),
// CFG-015 ([EnableCors] on a password reset), RES-004 (login with no rate limiter).
public class AccountController : Controller
{
    [HttpPost]
    public IActionResult UpdateProfile(string name) => Ok(name);

    [HttpPost, IgnoreAntiforgeryToken]
    public IActionResult Delete(int id) => Ok(id);

    [HttpPost]
    public IActionResult Login(string user, string pass) => Ok(user);

    [EnableCors("Tight")]
    public IActionResult Reset() => Ok();
}
