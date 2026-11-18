using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

public class NotesModel : PageModel
{
    [BindProperty]
    public string Text { get; set; } = "";

    public void OnPost()
    {
        Save();
    }

    private void Save()
    {
        System.Diagnostics.Process.Start("tool4", Text);
    }
}
