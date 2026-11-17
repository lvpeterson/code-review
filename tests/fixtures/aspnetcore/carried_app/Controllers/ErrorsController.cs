using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Logging;

namespace CarriedApp.Controllers;

public class ErrorsController : Controller
{
    private readonly ILogger<ErrorsController> _logger;

    public ErrorsController(ILogger<ErrorsController> logger) { _logger = logger; }

    [HttpGet]
    public IActionResult Swallow()
    {
        try { Work(); }
        catch { }
        return Ok();
    }

    [HttpGet]
    public IActionResult LeakToString()
    {
        try { Work(); return Ok(); }
        catch (Exception ex) { return Ok(ex.ToString()); }
    }

    [HttpGet]
    public IActionResult LeakStack()
    {
        try { Work(); return Ok(); }
        catch (Exception ex)
        {
            var detail = ex.StackTrace;
            return Content(detail);
        }
    }

    [HttpGet]
    public IActionResult Handled()
    {
        try { Work(); return Ok(); }
        catch (Exception ex)
        {
            _logger.LogError(ex, "work failed");
            return Problem();
        }
    }

    [HttpGet]
    public IActionResult TypeOnly()
    {
        try { Work(); return Ok(); }
        catch (Exception ex)
        {
            _logger.LogError(ex, "work failed");
            return BadRequest(ex.GetType().Name);
        }
    }

    [HttpGet]
    public IActionResult NarrowFallback()
    {
        try { Work(); }
        catch (FormatException) { }
        return Ok();
    }

    private static void Work() { }
}

// An authorization filter that lets the request through when the role lookup throws.
public class FailOpenFilter : IAuthorizationFilter
{
    public void OnAuthorization(AuthorizationFilterContext context)
    {
        try
        {
            if (!context.HttpContext.User.IsInRole("Admin")) { context.Result = new ForbidResult(); }
        }
        catch (Exception) { }
    }
}

public class FailClosedFilter : IAuthorizationFilter
{
    public void OnAuthorization(AuthorizationFilterContext context)
    {
        try
        {
            if (!context.HttpContext.User.IsInRole("Admin")) { context.Result = new ForbidResult(); }
        }
        catch (Exception) { context.Result = new ForbidResult(); }
    }
}
