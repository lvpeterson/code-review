using System.Security.Claims;
using static Misc3d.Services.AccessHelpers;

namespace Misc3d.Services;

public static class AccessHelpers
{
    public static bool CanGo(ClaimsPrincipal u)
    {
        return u.IsInRole("admin");
    }
}

public class StaticUsingGate
{
    public bool Handle(ClaimsPrincipal u)
    {
        try
        {
            var ok = CanGo(u);
            return ok;
        }
        catch (Exception)
        {
            return true;
        }
    }
}
