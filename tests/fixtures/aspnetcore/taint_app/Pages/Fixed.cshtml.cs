using Microsoft.AspNetCore.Mvc.RazorPages;

public class FixedModel : PageModel
{
    public string Note { get; set; } = "";

    public void OnGet()
    {
        Note = "constant";
    }
}
