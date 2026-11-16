using Microsoft.AspNetCore.Mvc;

namespace Shop.Controllers;

[Route("invoices")]
public class InvoicesController : BaseApiController
{
    [HttpPost]
    public IActionResult Create() => Ok();
}
