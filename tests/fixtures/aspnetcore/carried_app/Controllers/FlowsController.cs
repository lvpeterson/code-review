using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Logging;

namespace CarriedApp.Controllers;

public class FlowsController : Controller
{
    private readonly ILogger<FlowsController> _logger;
    private readonly SignInManager<IdentityUser> _signIn;
    private readonly HttpClient _http;

    public FlowsController(ILogger<FlowsController> logger, SignInManager<IdentityUser> signIn, HttpClient http)
    {
        _logger = logger;
        _signIn = signIn;
        _http = http;
    }

    [HttpPost]
    public async Task<IActionResult> Login(string user, string password)
    {
        var u = new IdentityUser(user);
        var result = await _signIn.CheckPasswordSignInAsync(u, password, false);
        if (!result.Succeeded)
        {
            _logger.LogWarning("failed sign-in for {User}", user);
            return Unauthorized();
        }
        return Ok();
    }

    [HttpPost]
    public async Task<IActionResult> SignInLocked(string user, string password)
    {
        var u = new IdentityUser(user);
        var result = await _signIn.CheckPasswordSignInAsync(u, password, lockoutOnFailure: true);
        if (!result.Succeeded)
        {
            _logger.LogWarning("failed sign-in for {User}", user);
            return Unauthorized();
        }
        return Ok();
    }

    [HttpPost]
    [EnableRateLimiting("auth")]
    public IActionResult Register(string user, string password)
    {
        _logger.LogInformation("registered {User}", user);
        return Ok();
    }

    // The upstream response is run as a command.
    [HttpGet]
    public async Task<IActionResult> Run()
    {
        var job = await _http.GetStringAsync("https://partner.example.com/job");
        System.Diagnostics.Process.Start(job);
        return Ok();
    }

    [HttpGet]
    public async Task<IActionResult> Show()
    {
        var body = await _http.GetStringAsync("https://partner.example.com/banner");
        return Content(body);
    }
}
