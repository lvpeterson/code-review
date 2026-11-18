using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Text.Encodings.Web;

[ApiController]
[Route("sink")]
public class SinkController : ControllerBase
{
    private readonly AppDb db;
    private readonly ILogger<SinkController> log;
    private readonly HttpClient http = new HttpClient();

    public SinkController(AppDb db, ILogger<SinkController> log)
    {
        this.db = db;
        this.log = log;
    }

    [HttpGet("raw-concat")]
    public IActionResult RawConcat(string term)
    {
        return Ok(db.Orders.FromSqlRaw("SELECT * FROM Orders WHERE Id = " + term).ToList());
    }

    [HttpGet("raw-interp")]
    public IActionResult RawInterp(string term)
    {
        return Ok(db.Orders.FromSqlRaw($"SELECT * FROM Orders WHERE Id = {term}").ToList());
    }

    [HttpGet("interp")]
    public IActionResult Interp(string term)
    {
        return Ok(db.Orders.FromSqlInterpolated($"SELECT * FROM Orders WHERE Id = {term}").ToList());
    }

    [HttpGet("fromsql")]
    public IActionResult FromSqlSafe(string term)
    {
        return Ok(db.Orders.FromSql($"SELECT * FROM Orders WHERE Id = {term}").ToList());
    }

    [HttpGet("exec")]
    public IActionResult Exec(string term)
    {
        db.Database.ExecuteSqlRaw("DELETE FROM Orders WHERE Id = " + term);
        return Ok();
    }

    [HttpGet("sqlcmd")]
    public IActionResult SqlCmd(string term)
    {
        var cmd = new Microsoft.Data.SqlClient.SqlCommand("SELECT " + term);
        return Ok(cmd.CommandText);
    }

    [HttpGet("go")]
    public IActionResult Go(string url)
    {
        return Redirect(url);
    }

    [HttpGet("go-local")]
    public IActionResult GoLocal(string url)
    {
        return LocalRedirect(url);
    }

    [HttpGet("go-guarded")]
    public IActionResult GoGuarded(string url)
    {
        if (Url.IsLocalUrl(url)) return Redirect(url);
        return BadRequest();
    }

    [HttpGet("file")]
    public IActionResult FileGet(string name)
    {
        return PhysicalFile(Path.Combine("/srv", name), "text/plain");
    }

    [HttpGet("file-safe")]
    public IActionResult FileSafe(string name)
    {
        return PhysicalFile(Path.Combine("/srv", Path.GetFileName(name)), "text/plain");
    }

    [HttpGet("hdr")]
    public IActionResult Hdr(string name)
    {
        Response.Headers["X-Echo"] = name;
        return Ok();
    }

    [HttpGet("cookie")]
    public IActionResult Cookie(string name)
    {
        Response.Cookies.Append("c", name);
        return Ok();
    }

    [HttpGet("log-interp")]
    public IActionResult LogInterp(string user)
    {
        log.LogInformation($"login {user}");
        return Ok();
    }

    [HttpGet("log-template")]
    public IActionResult LogTemplate(string user)
    {
        log.LogInformation("login {User}", user);
        return Ok();
    }

    [HttpGet("log-concat")]
    public IActionResult LogConcat(string user)
    {
        log.LogWarning("login " + user);
        return Ok();
    }

    [HttpGet("html")]
    public IActionResult Html(string name)
    {
        return Content(name, "text/html");
    }

    [HttpGet("json-ok")]
    public IActionResult JsonOk(string name)
    {
        return Content(name, "application/json");
    }

    [HttpGet("encoded")]
    public IActionResult Encoded(string name)
    {
        return Content(HtmlEncoder.Default.Encode(name), "text/html");
    }

    [HttpGet("fetch")]
    public async Task<IActionResult> Fetch(string url)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, url);
        var res = await http.SendAsync(req);
        return Ok(res.StatusCode);
    }
}
