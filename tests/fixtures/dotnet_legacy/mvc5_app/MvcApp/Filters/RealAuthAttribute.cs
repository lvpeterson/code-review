using System.Web.Http;
using System.Web.Http.Controllers;

namespace MvcApp.Filters
{
    public class RealAuthAttribute : AuthorizeAttribute
    {
        protected override bool IsAuthorized(HttpActionContext c)
        {
            if (c.RequestContext.Principal == null)
            {
                return false;
            }
            return c.RequestContext.Principal.Identity.IsAuthenticated;
        }
    }
}
