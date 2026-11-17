using System.IO;
using System.IO.Compression;
using Microsoft.AspNetCore.Mvc;

namespace TaintGaps.Controllers;

// Zip slip: the entry name is attacker-controlled whatever opened the archive.
[ApiController]
[Route("zip")]
public class ArchiveController : ControllerBase
{
    [HttpPost("slip-body")]
    public IActionResult SlipBody()
    {
        using var archive = new ZipArchive(Request.Body);
        foreach (var entry in archive.Entries)
        {
            var target = Path.Combine("/data", entry.FullName);
            using var s = System.IO.File.Create(target);
        }
        return Ok();
    }

    // The archive was saved earlier and is opened from disk: no request value reaches it.
    [HttpPost("slip-disk")]
    public IActionResult SlipDisk()
    {
        using var archive = ZipFile.OpenRead("/data/upload.zip");
        foreach (var entry in archive.Entries)
        {
            entry.ExtractToFile(Path.Combine("/data", entry.Name), true);
        }
        return Ok();
    }

    [HttpPost("slip-name")]
    public IActionResult SlipName()
    {
        using var archive = ZipFile.OpenRead("/data/upload.zip");
        foreach (var entry in archive.Entries)
        {
            System.IO.File.WriteAllText(Path.Combine("/data", entry.Name), "x");
        }
        return Ok();
    }

    [HttpGet("fixed")]
    public IActionResult Fixed()
    {
        using var archive = ZipFile.OpenRead("/data/upload.zip");
        return Ok(archive.Entries.Count);
    }
}
