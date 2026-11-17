using System.IO;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace TaintGaps.Controllers;

// StreamReader / StreamWriter over a stream is not a path sink; over a string path it is.
[ApiController]
[Route("streams")]
public class StreamsController : ControllerBase
{
    [HttpPost("body")] public IActionResult Body() { using var r = new StreamReader(Request.Body); return Ok(r.GetType().Name); }
    [HttpPost("respbody")] public IActionResult RespBody() { using var w = new StreamWriter(Response.Body); return Ok(); }
    [HttpPost("upload")] public IActionResult Upload(IFormFile file) { using var r = new StreamReader(file.OpenReadStream()); return Ok(); }
    [HttpPost("typed")] public IActionResult Typed(IFormFile file) { Stream s = file.OpenReadStream(); using var r = new StreamReader(s); return Ok(); }
    [HttpPost("inferred")] public IActionResult Inferred(IFormFile file) { var s = file.OpenReadStream(); using var r = new StreamReader(s); return Ok(); }
    [HttpPost("stringpath")] public IActionResult StringPath(string p) { using var r = new StreamReader(p); return Ok(); }
    [HttpPost("writerpath")] public IActionResult WriterPath(string p) { using var w = new StreamWriter(p); return Ok(); }
    [HttpPost("filestream")] public IActionResult FileStreamPath(string p) { using var f = new FileStream(p, FileMode.Open); return Ok(); }

    // A project method named like a stream factory that returns a path is still a path.
    private static string OpenRead(string name) => name;
    [HttpPost("useropen")] public IActionResult UserOpen(string p) { using var r = new StreamReader(OpenRead(p)); return Ok(); }
    [HttpPost("formpath")] public IActionResult FormPath() { var v = Request.Form["a"]; using var r = new StreamReader(v); return Ok(); }
}
