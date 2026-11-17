using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace CarriedApp.Controllers;

public class SessionController : Controller
{
    private readonly IPasswordHasher<IdentityUser> _hasher;
    private readonly Dictionary<string, string> _plain = new();

    public SessionController(IPasswordHasher<IdentityUser> hasher) { _hasher = hasher; }

    [HttpPost]
    public IActionResult Check(string user, string password)
    {
        if (password == _plain[user])
        {
            HttpContext.Session.SetString("user", user);
            return Ok();
        }
        return Unauthorized();
    }

    [HttpPost]
    public IActionResult CheckHashed(string user, string password)
    {
        var u = new IdentityUser(user);
        var res = _hasher.VerifyHashedPassword(u, _plain[user], password);
        if (res == PasswordVerificationResult.Success)
        {
            HttpContext.Session.SetString("user", user);
            return Ok();
        }
        return Unauthorized();
    }
}
