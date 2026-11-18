using Microsoft.AspNetCore.Mvc;
using TaintApp.Services;

[ApiController]
[Route("bind")]
public class BindController : ControllerBase
{
    [BindProperty]
    public string Note { get; set; } = "";

    [HttpGet("di")]
    public IActionResult Di(IReport report)
    {
        System.Diagnostics.Process.Start("tool", report.Query);
        return Ok();
    }

    [HttpGet("fs")]
    public IActionResult Fs([FromServices] Auditor a)
    {
        System.Diagnostics.Process.Start("tool", a.Sql);
        return Ok();
    }

    [HttpPost("dto")]
    public IActionResult Dto(TaintApp.Models.ReportRequest req)
    {
        System.Diagnostics.Process.Start("tool", req.Query);
        return Ok();
    }

    [HttpPost("decoy")]
    public IActionResult Decoy(TaintApp.Models.Auditor a)
    {
        System.Diagnostics.Process.Start("tool", a.Sql);
        return Ok();
    }

    [HttpGet("ctx")]
    public IActionResult Ctx(HttpContext ctx, CancellationToken ct, ILogger<BindController> log)
    {
        var x = log.ToString();
        System.Diagnostics.Process.Start("tool", x);
        return Ok();
    }

    [HttpPost("upload")]
    public IActionResult Upload(IFormFile file)
    {
        var x = file.FileName;
        System.Diagnostics.Process.Start("tool", x);
        return Ok();
    }

    [HttpGet("req")]
    public IActionResult Req(HttpRequest request)
    {
        System.Diagnostics.Process.Start("tool", request.Query["q"]);
        return Ok();
    }

    [HttpGet("req2")]
    public IActionResult Req2(HttpRequest r)
    {
        System.Diagnostics.Process.Start("tool", r.Query["q"]);
        return Ok();
    }

    // A controller action that merely looks like a Razor Page handler: its verb is the attribute's.
    [HttpPost("ongetx")]
    public IActionResult OnGetX()
    {
        System.Diagnostics.Process.Start("tool", Note);
        return Ok();
    }
}
