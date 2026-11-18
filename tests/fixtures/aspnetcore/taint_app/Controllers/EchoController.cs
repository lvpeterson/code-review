using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;

[ApiController]
[Route("echo")]
public class EchoController : ControllerBase
{
    [HttpGet("cmd")]
    public IActionResult Cmd()
    {
        var a = HttpContext.Request.Query["a"].ToString();
        System.Diagnostics.Process.Start("tool", a);
        return Ok();
    }

    [HttpPost("body")]
    public async Task<IActionResult> Body()
    {
        var s = await new StreamReader(Request.Body).ReadToEndAsync();
        System.IO.File.ReadAllText(s);
        return Ok();
    }

    [HttpGet("route/{v}")]
    public IActionResult Route()
    {
        var v = HttpContext.GetRouteValue("v")?.ToString();
        System.IO.File.Delete(v!);
        return Ok();
    }

    [HttpGet("hdr")]
    public IActionResult Hdr()
    {
        var h = Request.Headers["X-Path"].ToString();
        System.IO.File.ReadAllText(h);
        return Ok();
    }

    [HttpGet("const")]
    public IActionResult Const()
    {
        System.Diagnostics.Process.Start("tool", "fixed");
        return Ok();
    }
}
