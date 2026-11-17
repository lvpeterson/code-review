using Microsoft.AspNetCore.Mvc;

namespace TaintGaps.Controllers;

// SSRF where only a path is attacker-controlled versus a fully tainted URL.
[ApiController]
[Route("fetch")]
public class FetchController : ControllerBase
{
    private const string BaseConst = "https://api.example.test/";
    private readonly HttpClient _http;
    private readonly IConfiguration _config;
    private readonly string _baseUrl;

    public FetchController(HttpClient http, IConfiguration config)
    {
        _http = http;
        _config = config;
        _baseUrl = config["Base"] ?? "";
    }

    [HttpGet("relative")] public async Task<IActionResult> Relative(string id) => Ok(await _http.GetStringAsync($"users/token/{id}"));
    [HttpGet("concat")] public async Task<IActionResult> Concat(string id) => Ok(await _http.GetStringAsync("todos/" + id));
    [HttpGet("fieldprefix")] public async Task<IActionResult> FieldPrefix(string id) => Ok(await _http.GetStringAsync($"{_baseUrl}{id}"));
    [HttpGet("constprefix")] public async Task<IActionResult> ConstPrefix(string id) => Ok(await _http.GetStringAsync($"{BaseConst}{id}"));

    [HttpGet("localprefix")]
    public async Task<IActionResult> LocalPrefix(string id)
    {
        var baseUrl = _config["Other"];
        return Ok(await _http.GetStringAsync(baseUrl + id));
    }

    [HttpGet("viavar")]
    public async Task<IActionResult> ViaVar(string id)
    {
        var url = $"items/{id}";
        return Ok(await _http.GetStringAsync(url));
    }

    // Controls: the attacker controls the whole URL or its scheme and host.
    [HttpGet("full")] public async Task<IActionResult> Full(string url) => Ok(await _http.GetStringAsync(url));
    [HttpGet("hostfirst")] public async Task<IActionResult> HostFirst(string host) => Ok(await _http.GetStringAsync($"{host}/x"));
    [HttpGet("schemeonly")] public async Task<IActionResult> SchemeOnly(string host) => Ok(await _http.GetStringAsync("https://" + host));
    [HttpGet("hostnoslash")] public async Task<IActionResult> HostNoSlash(string p) => Ok(await _http.GetStringAsync("https://api.example.test" + p));
}
