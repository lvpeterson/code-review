namespace RazorApp.Models;

// A same-named type outside the page namespaces: the page must not bind to it.
public class CartModel
{
    public int Items { get; set; }
    public void OnGet() { }
}
