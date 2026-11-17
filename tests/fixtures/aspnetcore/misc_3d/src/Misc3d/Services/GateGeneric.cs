using System.Security.Claims;

namespace Misc3d.Services;

public class GateBase<T>
{
    protected bool CanLeave(ClaimsPrincipal u)
    {
        return u.IsInRole("admin");
    }
}

public class GenericGate : GateBase<int>
{
    public bool Handle(ClaimsPrincipal u)
    {
        try
        {
            var ok = CanLeave(u);
            return ok;
        }
        catch (Exception)
        {
            return true;
        }
    }
}
