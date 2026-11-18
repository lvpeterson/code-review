using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace RazorApp.Pages.Admin;

public class LoginModel : PageModel
{
    public void OnGet() { }

    public IActionResult OnPost() => RedirectToPage("/Index");
}
