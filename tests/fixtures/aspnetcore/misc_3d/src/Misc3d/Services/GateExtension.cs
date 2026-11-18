using System.Security.Claims;

namespace Misc3d.Services;

public static class GateExtensions
{
    public static bool CanEnter(this ExtensionGate g, ClaimsPrincipal u)
    {
        return u.IsInRole("admin");
    }
}

public class ExtensionGate
{
    public bool Handle(ClaimsPrincipal u)
    {
        try
        {
            var ok = this.CanEnter(u);
            return ok;
        }
        catch (Exception)
        {
            return true;
        }
    }
}
