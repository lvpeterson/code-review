using Microsoft.AspNetCore.Mvc;

namespace Misc3d.Tests;

[ApiController]
[Route("fake")]
public class FakeProxyController : ControllerBase
{
    private readonly HttpClient http = new HttpClient();
    private const string TestPassword = "Tr0ub4dor&3xK9!";

    [HttpGet("fetch")]
    public async Task<IActionResult> Fetch(string url)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, url);
        var res = await http.SendAsync(req);
        return Ok(res.StatusCode);
    }
}
