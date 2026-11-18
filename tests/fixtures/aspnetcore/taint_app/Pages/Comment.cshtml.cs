using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

public class CommentModel : PageModel
{
    [BindProperty]
    public string Text { get; set; } = "";

    [BindProperty(SupportsGet = true)]
    public string Q { get; set; } = "";

    public void OnGet()
    {
        System.Diagnostics.Process.Start("tool", Text);
        System.Diagnostics.Process.Start("tool2", Q);
    }

    public void OnPost()
    {
        System.Diagnostics.Process.Start("tool3", Text);
    }
}
