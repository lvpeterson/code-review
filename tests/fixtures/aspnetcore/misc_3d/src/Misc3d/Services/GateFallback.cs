using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;

namespace Misc3d.Services;

public class FallbackHelpers
{
    public bool CanSeeIt(ClaimsPrincipal u)
    {
        return u.IsInRole("admin");
    }
}

public class FallbackGate : ControllerBase
{
    public bool Handle(ClaimsPrincipal u)
    {
        try
        {
            var ok = CanSeeIt(u);
            return ok;
        }
        catch (Exception)
        {
            return true;
        }
    }
}
