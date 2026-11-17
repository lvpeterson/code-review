using System.Security.Claims;

namespace Misc3d.Services;

// Same method name as the nested gate's helper, unrelated to it.
public class DecoyReader
{
    public bool CanProceed(ClaimsPrincipal u)
    {
        return u.Identity != null && u.Identity.IsAuthenticated;
    }
}
