using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace RazorApp.Areas.Shop.Pages;

[Authorize]
public class CartModel : PageModel
{
    public void OnGet() { }

    public IActionResult OnPostCheckout() => RedirectToPage("/Index");
}
