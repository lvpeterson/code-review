using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Misc3d.Services;

namespace Misc3d.Pages;

public class CheckoutModel : PageModel
{
    private readonly ICartService _cart;

    public CheckoutModel(ICartService cart) { _cart = cart; }

    private Task LoadCart()
    {
        return _cart.Update(0);
    }

    public async Task<IActionResult> OnPost(int id)
    {
        try
        {
            await LoadCart();
            if (!ModelState.IsValid)
            {
                return BadRequest();
            }
            await _cart.Update(id);
            await _cart.PlaceOrder(id);
        }
        catch (EmptyCartException)
        {
            return RedirectToPage("/Index");
        }
        return RedirectToPage("/Done");
    }
}
