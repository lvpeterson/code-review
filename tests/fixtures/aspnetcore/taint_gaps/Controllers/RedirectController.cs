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

    // Controls: a guard that does not exit must not cleanse the other path, nor survive reassigning its root.
    [HttpPost("noexit")]
    public IActionResult NoExit([FromBody] ReturnModel model)
    {
        if (Url.IsLocalUrl(model.ReturnUrl)) { var x = 1; }
        return Redirect(model.ReturnUrl);
    }

    [HttpPost("reassign")]
    public IActionResult Reassign([FromBody] ReturnModel model, [FromQuery] ReturnModel m2)
    {
        if (!Url.IsLocalUrl(model.ReturnUrl)) { return BadRequest(); }
        model = m2;
        return Redirect(model.ReturnUrl);
    }

    // Control: a guard on an earlier, separate `item` must not cleanse a later loop variable of the same name.
    [HttpPost("loopshadow")]
    public IActionResult LoopShadow([FromQuery] ReturnModel m2, [FromQuery] List<ReturnModel> xs)
    {
        {
            var item = m2;
            if (!Url.IsLocalUrl(item.ReturnUrl)) { return BadRequest(); }
        }
        foreach (var item in xs) { return Redirect(item.ReturnUrl); }
        return Ok();
    }
}
