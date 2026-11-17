using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using TaintApp.Models;

public class EditOrderModel : PageModel
{
    private readonly AppDb db;

    public EditOrderModel(AppDb db)
    {
        this.db = db;
    }

    [BindProperty]
    public Order Item { get; set; } = new();

    public IActionResult OnPost()
    {
        db.Update(Item);
        db.SaveChanges();
        return Page();
    }
}
