using Microsoft.AspNetCore.Mvc;

namespace Misc3d.Services;

[ApiController]
[Route("proxy")]
public class ProxyController : ControllerBase
{
    private readonly HttpClient http = new HttpClient();

    [HttpGet("fetch")]
    public async Task<IActionResult> Fetch(string url)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, url);
        var res = await http.SendAsync(req);
        return Ok(res.StatusCode);
    }
}
