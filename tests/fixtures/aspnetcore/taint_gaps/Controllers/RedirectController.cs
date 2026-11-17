using Microsoft.AspNetCore.Mvc;

namespace TaintGaps.Controllers;

public class ReturnModel
{
    public string ReturnUrl { get; set; } = "";
    public string Other { get; set; } = "";
}

// IsLocalUrl guards over member-access paths.
[ApiController]
[Route("redir")]
public class RedirectController : ControllerBase
{
    [HttpPost("then")]
    public IActionResult Then([FromBody] ReturnModel model)
    {
        if (Url.IsLocalUrl(model.ReturnUrl)) { return Redirect(model.ReturnUrl); }
        return BadRequest();
    }

    [HttpPost("early")]
    public IActionResult Early([FromBody] ReturnModel model)
    {
        if (!Url.IsLocalUrl(model.ReturnUrl)) { return BadRequest(); }
        return Redirect(model.ReturnUrl);
    }

    [HttpPost("simple")]
    public IActionResult Simple(string returnUrl)
    {
        if (Url.IsLocalUrl(returnUrl)) { return Redirect(returnUrl); }
        return BadRequest();
    }

    // Controls: no guard, or a guard on another member, still flag.
    [HttpPost("unguarded")]
    public IActionResult Unguarded([FromBody] ReturnModel model) { return Redirect(model.ReturnUrl); }

    [HttpPost("othermember")]
    public IActionResult OtherMember([FromBody] ReturnModel model)
    {
        if (Url.IsLocalUrl(model.ReturnUrl)) { return Redirect(model.Other); }
        return BadRequest();
    }
}
