using Microsoft.AspNetCore.Mvc;
using TaintApp.Models;

public class FormsController : Controller
{
    private readonly AppDb db;

    public FormsController(AppDb db)
    {
        this.db = db;
    }

    [HttpPost]
    public async Task<IActionResult> Edit(int id)
    {
        var o = db.Orders.Find(id);
        await TryUpdateModelAsync(o);
        db.SaveChanges();
        return View();
    }

    [HttpPost]
    public async Task<IActionResult> EditSafe(int id)
    {
        var o = db.Orders.Find(id);
        await TryUpdateModelAsync(o, "", x => x.Total);
        db.SaveChanges();
        return View();
    }

    [HttpPost]
    public IActionResult Bound([Bind("Total")] Order o)
    {
        db.Update(o);
        return View();
    }
}
