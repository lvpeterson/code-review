using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace RazorApp.Pages.Orders;

public class EditModel : PageModel
{
    public void OnGet(int id) { }

    [Authorize]
    public IActionResult OnPostSave() => RedirectToPage("/Index");
}
