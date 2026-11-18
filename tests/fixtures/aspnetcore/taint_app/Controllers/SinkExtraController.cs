using Microsoft.AspNetCore.Html;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using System.Net.Mime;
using System.Text.Encodings.Web;

[ApiController]
[Route("sink2")]
public class SinkExtraController : ControllerBase
{
    private readonly ILogger<SinkExtraController> log;

    public SinkExtraController(ILogger<SinkExtraController> log)
    {
        this.log = log;
    }

    [HttpGet("log-ex")]
    public IActionResult LogEx(string user)
    {
        log.LogError(new Exception("boom"), $"failed {user}");
        return Ok();
    }

    [HttpGet("log-ex-template")]
    public IActionResult LogExTemplate(string user)
    {
        try { return Ok(); }
        catch (Exception ex)
        {
            log.LogError(ex, "failed {User}", user);
            return Problem();
        }
    }

    [HttpGet("content-plain")]
    public IActionResult ContentPlain(string name)
    {
        return Content(name);
    }

    [HttpGet("content-media")]
    public IActionResult ContentMedia(string name)
    {
        return Content(name, MediaTypeNames.Text.Plain);
    }

    [HttpGet("hdr-append")]
    public IActionResult HdrAppend(string name)
    {
        Response.Headers.Append("X-Echo", name);
        return Ok();
    }

    [HttpGet("dict-add")]
    public IActionResult DictAdd(string name)
    {
        IDictionary<string, string> d = new Dictionary<string, string>();
        d.Add("k", name);
        return Ok(d);
    }

    [HttpGet("html-string")]
    public IActionResult HtmlStr(string name)
    {
        return Ok(new HtmlString(name));
    }

    [HttpGet("url-encoded")]
    public IActionResult UrlEnc(string name)
    {
        return Ok(new HtmlString(UrlEncoder.Default.Encode(name)));
    }

    [HttpGet("resp-redirect")]
    public IActionResult RespRedirect(string url)
    {
        Response.Redirect(url);
        return new EmptyResult();
    }

    [HttpGet("new-redirect")]
    public IActionResult NewRedirect(string url)
    {
        return new RedirectResult(url);
    }

    [HttpGet("display-url")]
    public IActionResult DisplayUrl()
    {
        System.Diagnostics.Process.Start("tool", Request.GetDisplayUrl());
        return Ok();
    }

    [HttpGet("protocol")]
    public IActionResult Protocol()
    {
        System.Diagnostics.Process.Start("tool", Request.Protocol);
        return Ok();
    }
}
