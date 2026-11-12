using System.Web;
using System.Web.Mvc;

namespace MvcApp.Filters
{
    // Looks like an auth filter but lets every request through.
    public class AlwaysAllowAttribute : AuthorizeAttribute
    {
        protected override bool AuthorizeCore(HttpContextBase c) { return true; }
    }
}
