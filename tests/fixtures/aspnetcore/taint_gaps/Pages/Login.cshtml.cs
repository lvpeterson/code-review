using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace TaintGaps.Pages;

public class LoginModel : PageModel
{
    public class InputModel
    {
        public string ReturnUrl { get; set; } = "";
    }

    [BindProperty] public InputModel Input { get; set; } = new();
    [BindProperty] public string ReturnUrl { get; set; } = "";
    [BindProperty] public string Other { get; set; } = "";

    public IActionResult OnPostInput()
    {
        if (Url.IsLocalUrl(Input.ReturnUrl)) { return Redirect(Input.ReturnUrl); }
        return Page();
    }

    public IActionResult OnPostThis()
    {
        if (!Url.IsLocalUrl(this.ReturnUrl)) { return Page(); }
        return Redirect(this.ReturnUrl);
    }

    // Control: the guard is on a different member.
    public IActionResult OnPostOther()
    {
        if (Url.IsLocalUrl(Input.ReturnUrl)) { return Redirect(Other); }
        return Page();
    }
}
