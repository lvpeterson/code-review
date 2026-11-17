using System.IO;
using System.IO.Compression;
using Microsoft.AspNetCore.Mvc;

namespace TaintGaps.Controllers;

// One action per path sink; `p` is the request-bound path.
[ApiController]
[Route("files")]
public class FileSinksController : ControllerBase
{
    [HttpGet("create")] public IActionResult Create(string p) { using var s = System.IO.File.Create(p); return Ok(); }
    [HttpGet("createtext")] public IActionResult CreateText(string p) { using var s = System.IO.File.CreateText(p); return Ok(); }
    [HttpGet("appendtext")] public IActionResult AppendText(string p) { using var s = System.IO.File.AppendText(p); return Ok(); }
    [HttpGet("appendalllines")] public IActionResult AppendAllLines(string p) { System.IO.File.AppendAllLines(p, new[] { "x" }); return Ok(); }
    [HttpGet("appendalllinesasync")] public async Task<IActionResult> AppendAllLinesAsync(string p) { await System.IO.File.AppendAllLinesAsync(p, new[] { "x" }); return Ok(); }
    [HttpGet("readlines")] public IActionResult ReadLines(string p) { var l = System.IO.File.ReadLines(p).ToList(); return Ok(l); }
    [HttpGet("readalltextasync")] public async Task<IActionResult> ReadAllTextAsync(string p) { return Ok(await System.IO.File.ReadAllTextAsync(p)); }
    [HttpGet("readallbytesasync")] public async Task<IActionResult> ReadAllBytesAsync(string p) { return Ok(await System.IO.File.ReadAllBytesAsync(p)); }
    [HttpGet("readalllinesasync")] public async Task<IActionResult> ReadAllLinesAsync(string p) { return Ok(await System.IO.File.ReadAllLinesAsync(p)); }
    [HttpGet("writealltextasync")] public async Task<IActionResult> WriteAllTextAsync(string p) { await System.IO.File.WriteAllTextAsync(p, "x"); return Ok(); }
    [HttpGet("writeallbytesasync")] public async Task<IActionResult> WriteAllBytesAsync(string p) { await System.IO.File.WriteAllBytesAsync(p, new byte[1]); return Ok(); }
    [HttpGet("writealllinesasync")] public async Task<IActionResult> WriteAllLinesAsync(string p) { await System.IO.File.WriteAllLinesAsync(p, new[] { "x" }); return Ok(); }
    [HttpGet("appendalltextasync")] public async Task<IActionResult> AppendAllTextAsync(string p) { await System.IO.File.AppendAllTextAsync(p, "x"); return Ok(); }
    [HttpGet("replace")] public IActionResult Replace(string p) { System.IO.File.Replace("a.tmp", p, null); return Ok(); }
    [HttpGet("enumfiles")] public IActionResult EnumFiles(string p) { return Ok(System.IO.Directory.EnumerateFiles(p).ToList()); }
    [HttpGet("enumdirs")] public IActionResult EnumDirs(string p) { return Ok(System.IO.Directory.EnumerateDirectories(p).ToList()); }
    [HttpGet("enumentries")] public IActionResult EnumEntries(string p) { return Ok(System.IO.Directory.EnumerateFileSystemEntries(p).ToList()); }
    [HttpGet("getdirs")] public IActionResult GetDirs(string p) { return Ok(System.IO.Directory.GetDirectories(p)); }
    [HttpGet("move")] public IActionResult Move(string p) { System.IO.Directory.Move("a", p); return Ok(); }
    [HttpGet("extract")] public IActionResult Extract(string p) { ZipFile.ExtractToDirectory("a.zip", p); return Ok(); }
    [HttpGet("createzip")] public IActionResult CreateZip(string p) { ZipFile.CreateFromDirectory("src", p); return Ok(); }
    [HttpGet("openzip")] public IActionResult OpenZip(string p) { using var z = ZipFile.Open(p, ZipArchiveMode.Read); return Ok(); }
    [HttpGet("entryto")]
    public IActionResult EntryTo(string p)
    {
        using var z = ZipFile.OpenRead("fixed.zip");
        foreach (var entry in z.Entries) { entry.ExtractToFile(p, true); }
        return Ok();
    }

    // Control: constant paths are not findings.
    [HttpGet("fixed")]
    public IActionResult Fixed()
    {
        using var s = System.IO.File.Create("out.txt");
        return Ok(System.IO.Directory.GetDirectories("/data"));
    }
}
