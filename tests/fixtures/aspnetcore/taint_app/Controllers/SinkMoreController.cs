using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Http.Headers;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Net.Http.Json;
using System.Text.Encodings.Web;

[ApiController]
[Route("sink3")]
public class SinkMoreController : ControllerBase
{
    private readonly AppDb db;
    private readonly ILogger<SinkMoreController> log;
    private readonly HttpClient http = new HttpClient();

    public SinkMoreController(AppDb db, ILogger<SinkMoreController> log)
    {
        this.db = db;
        this.log = log;
    }

    [HttpGet("sqlquery")]
    public IActionResult SqlQuerySafe(string term)
    {
        return Ok(db.Database.SqlQuery<int>($"SELECT {term}").ToList());
    }

    [HttpGet("json-fetch")]
    public async Task<IActionResult> JsonFetch(string url)
    {
        return Ok(await http.GetFromJsonAsync<int>(url));
    }

    [HttpGet("json-post")]
    public async Task<IActionResult> JsonPost(string url)
    {
        await http.PostAsJsonAsync(url, 1);
        return Ok();
    }

    [HttpGet("patch")]
    public async Task<IActionResult> PatchIt(string url)
    {
        await http.PatchAsync(url, null);
        return Ok();
    }

    [HttpGet("fetch-init")]
    public async Task<IActionResult> FetchInit(string url)
    {
        var req = new HttpRequestMessage { RequestUri = new Uri(url) };
        var res = await http.SendAsync(req);
        return Ok(res.StatusCode);
    }

    [HttpGet("text-html")]
    public IActionResult TextHtml(string name)
    {
        return Ok(Results.Text(name, "text/html"));
    }

    [HttpGet("text-plain")]
    public IActionResult TextPlain(string name)
    {
        return Ok(Results.Text(name, "text/plain"));
    }

    [HttpGet("cr-html")]
    public IActionResult ContentResultHtml(string name)
    {
        return new ContentResult { Content = name, ContentType = "text/html" };
    }

    [HttpGet("cr-plain")]
    public IActionResult ContentResultPlain(string name)
    {
        return new ContentResult { Content = name };
    }

    [HttpGet("cr-json")]
    public IActionResult ContentResultJson(string name)
    {
        return new ContentResult { Content = name, ContentType = "application/json" };
    }

    [HttpGet("xml")]
    public IActionResult ContentXml(string name)
    {
        return Content(name, "application/xml");
    }

    [HttpGet("svg")]
    public IActionResult ContentSvg(string name)
    {
        return Content(name, "image/svg+xml");
    }

    [HttpGet("unsafe-enc")]
    public IActionResult UnsafeEnc(string name)
    {
        return Content(JavaScriptEncoder.UnsafeRelaxedJsonEscaping.Encode(name), "text/html");
    }

    [HttpGet("log-level")]
    public IActionResult LogLevelVar(string user)
    {
        var level = Enum.Parse<LogLevel>("Information");
        log.Log(level, $"x {user}");
        return Ok();
    }

    [HttpGet("log-event")]
    public IActionResult LogEventVar(string user)
    {
        var eventId = new EventId(7);
        log.LogInformation(eventId, $"x {user}");
        return Ok();
    }

    [HttpGet("scope")]
    public IActionResult ScopeNamed(string user)
    {
        using (log.BeginScope(messageFormat: "scope " + user)) { }
        return Ok();
    }

    [HttpGet("markup")]
    public IActionResult MarkupCast(string name)
    {
        var m = (MarkupString)name;
        return Ok(m);
    }

    [HttpGet("loc-hdr")]
    public IActionResult LocationHdr(string url)
    {
        Response.Headers.Location = url;
        return Ok();
    }

    [HttpGet("loc-typed")]
    public IActionResult TypedLoc(string url)
    {
        Response.GetTypedHeaders().Location = new Uri(url);
        return Ok();
    }

    [HttpGet("sendfile")]
    public async Task<IActionResult> SendFile(string name)
    {
        await Response.SendFileAsync(name);
        return Ok();
    }

    [HttpGet("virtual")]
    public IActionResult Virt(string name)
    {
        return VirtualFile(name, "text/plain");
    }

    [HttpGet("file-ctor")]
    public IActionResult FileResultCtor(string name)
    {
        return new PhysicalFileResult(name, "text/plain");
    }
}
