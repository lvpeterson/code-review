using Microsoft.AspNetCore.Mvc;
using CarriedApp.Data;

namespace CarriedApp.Controllers;

public class UploadController : Controller
{
    private const long MaxBytes = 1_000_000;
    private readonly AppDb _db;

    public UploadController(AppDb db) { _db = db; }

    [HttpPost]
    public async Task<IActionResult> Save(IFormFile file)
    {
        using var stream = System.IO.File.Create("/tmp/" + Path.GetFileName(file.FileName));
        await file.CopyToAsync(stream);
        return Ok();
    }

    [HttpPost]
    public async Task<IActionResult> SaveChecked(IFormFile file)
    {
        if (file.Length > MaxBytes)
        {
            return BadRequest();
        }
        using var stream = System.IO.File.Create("/tmp/" + Path.GetFileName(file.FileName));
        await file.CopyToAsync(stream);
        return Ok();
    }

    [HttpGet]
    public IActionResult Everything(int pageSize)
    {
        return Ok(_db.Orders.ToList());
    }

    [HttpGet]
    public IActionResult Page(int pageSize)
    {
        return Ok(_db.Orders.Take(Math.Min(pageSize, 100)).ToList());
    }
}

// A diagnostics endpoint shipped in the production project.
public class DiagnosticsController : Controller
{
    [HttpGet]
    public IActionResult Index() => Ok();
}
