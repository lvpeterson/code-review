using System.Security.Claims;

namespace Misc3d.Services;

public class NestedOuter
{
    private static bool CanProceed(ClaimsPrincipal u)
    {
        return u.IsInRole("admin");
    }

    public class Inner
    {
        public bool Handle(ClaimsPrincipal u)
        {
            try
            {
                var ok = CanProceed(u);
                return ok;
            }
            catch (Exception)
            {
                return true;
            }
        }
    }
}
