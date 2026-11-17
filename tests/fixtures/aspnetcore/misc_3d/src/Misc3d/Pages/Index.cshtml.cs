using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Misc3d.Pages;

public class IndexModel : PageModel
{
    public string Greeting { get; set; } = "";

    public void OnGet()
    {
        LoadCart();
    }

    private void LoadCart()
    {
        if (User.Identity != null && User.Identity.IsAuthenticated)
        {
            Greeting = User.Identity.Name ?? "";
        }
    }
}
