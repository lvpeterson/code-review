using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace RazorApp.Pages.Admin;

public class UsersModel : PageModel
{
    public void OnGet(int? id) { }

    public async Task<IActionResult> OnPostDeleteAsync(int id)
    {
        await Task.CompletedTask;
        return RedirectToPage();
    }

    public string Describe() => "not a handler";
}
