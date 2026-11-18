using Microsoft.AspNetCore.Mvc;

namespace ConfigApp.Controllers;

public class ItemDb
{
    public IQueryable<string> Items => new List<string>().AsQueryable();
}

// ApiController: RES-005 (page size reaches Take unchecked) and two API versions in the path
// (INV-004 reports the older one).
[ApiController]
[Route("api/v1/items")]
public class ItemsController : ControllerBase
{
    private readonly ItemDb db = new();

    [HttpGet]
    public IActionResult List(int pageSize) => Ok(db.Items.Take(pageSize).ToList());
}

[ApiController]
[Route("api/v2/items")]
public class ItemsV2Controller : ControllerBase
{
    [HttpGet]
    public IActionResult List() => Ok();
}
