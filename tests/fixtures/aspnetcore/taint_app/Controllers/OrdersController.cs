using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using TaintApp.Models;

[ApiController]
[Route("orders")]
public class OrdersController : ControllerBase
{
    private readonly AppDb db;
    private readonly IAuthorizationService authz;

    public OrdersController(AppDb db, IAuthorizationService authz)
    {
        this.db = db;
        this.authz = authz;
    }

    [HttpGet("{id}")]
    public IActionResult Get(int id) => Ok(db.Orders.Find(id));

    [HttpGet("mine/{id}")]
    public IActionResult Mine(int id)
    {
        var uid = User.FindFirstValue(ClaimTypes.NameIdentifier);
        var o = db.Orders.Find(id);
        if (o == null || o.OwnerId != uid) return Forbid();
        return Ok(o);
    }

    [HttpGet("authz/{id}")]
    public async Task<IActionResult> Authz(int id)
    {
        var o = db.Orders.Find(id);
        var r = await authz.AuthorizeAsync(User, o, "Owner");
        if (!r.Succeeded) return Forbid();
        return Ok(o);
    }

    [HttpPut("{id}")]
    public IActionResult Put(int id, Order o)
    {
        db.Update(o);
        db.SaveChanges();
        return Ok();
    }

    [HttpPut("dto/{id}")]
    public IActionResult PutDto(int id, OrderDto dto)
    {
        var o = new Order { Id = id, Total = dto.Total };
        db.Update(o);
        db.SaveChanges();
        return Ok();
    }

    [HttpGet("users")]
    public IActionResult Users() => Ok(db.Users.ToList());

    [HttpGet("orders")]
    public IActionResult All() => Ok(db.Orders.ToList());
}
