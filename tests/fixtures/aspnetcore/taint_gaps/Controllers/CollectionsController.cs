using System.Diagnostics;
using System.IO;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace TaintGaps.Controllers;

// TryGetValue on request collections and readers over the request body; the sink is a command.
[ApiController]
[Route("coll")]
public class CollectionsController : ControllerBase
{
    [HttpGet("query")]
    public IActionResult Query()
    {
        if (Request.Query.TryGetValue("c", out var v)) { Process.Start("tool", v.ToString()); }
        return Ok();
    }

    [HttpPost("form")]
    public IActionResult Form()
    {
        if (Request.Form.TryGetValue("c", out var v)) { Process.Start("tool", v.ToString()); }
        return Ok();
    }

    [HttpGet("header")]
    public IActionResult Header()
    {
        if (Request.Headers.TryGetValue("X-C", out var v)) { Process.Start("tool", v.ToString()); }
        return Ok();
    }

    [HttpGet("cookie")]
    public IActionResult Cookie()
    {
        if (Request.Cookies.TryGetValue("c", out string v)) { Process.Start("tool", v); }
        return Ok();
    }

    [HttpGet("route")]
    public IActionResult RouteVal()
    {
        if (Request.RouteValues.TryGetValue("c", out var v)) { Process.Start("tool", v.ToString()); }
        return Ok();
    }

    [HttpGet("typed")]
    public IActionResult Typed(IQueryCollection q)
    {
        if (q.TryGetValue("c", out var v)) { Process.Start("tool", v.ToString()); }
        return Ok();
    }

    // Control: a dictionary of constants.
    [HttpGet("dict")]
    public IActionResult Dict()
    {
        var d = new Dictionary<string, string> { ["a"] = "b" };
        if (d.TryGetValue("a", out var v)) { Process.Start("tool", v); }
        return Ok();
    }

    [HttpPost("readtoend")]
    public async Task<IActionResult> ReadToEnd()
    {
        using var reader = new StreamReader(Request.Body);
        var text = await reader.ReadToEndAsync();
        Process.Start("tool", text);
        return Ok();
    }

    [HttpPost("readtoendsync")]
    public IActionResult ReadToEndSync()
    {
        var text = new StreamReader(Request.Body).ReadToEnd();
        Process.Start("tool", text);
        return Ok();
    }

    [HttpPost("readline")]
    public async Task<IActionResult> ReadLine()
    {
        using var reader = new StreamReader(Request.Body);
        var line = await reader.ReadLineAsync();
        Process.Start("tool", line!);
        return Ok();
    }

    [HttpPost("upload")]
    public async Task<IActionResult> Upload(IFormFile file)
    {
        using var reader = new StreamReader(file.OpenReadStream());
        var text = await reader.ReadToEndAsync();
        Process.Start("tool", text);
        return Ok();
    }

    // Control: a reader over a fixed file.
    [HttpGet("fixedreader")]
    public IActionResult FixedReader()
    {
        using var reader = new StreamReader("/data/fixed.txt");
        Process.Start("tool", reader.ReadToEnd());
        return Ok();
    }
}
