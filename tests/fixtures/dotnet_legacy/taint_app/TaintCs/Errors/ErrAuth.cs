using System;
using System.Security.Principal;
using System.Web;
using System.Web.Mvc;

namespace TaintCs.Errors
{
    // ERR-001: fail-open catches around an authorization decision.
    public class FailOpenAttribute : AuthorizeAttribute
    {
        protected override bool AuthorizeCore(HttpContextBase httpContext)
        {
            try
            {
                return httpContext.User.IsInRole("admin");
            }
            catch
            {
                return true;
            }
        }
    }

    public class FailSafeAttribute : AuthorizeAttribute
    {
        protected override bool AuthorizeCore(HttpContextBase httpContext)
        {
            try
            {
                return httpContext.User.IsInRole("admin");
            }
            catch
            {
                return false;
            }
        }
    }

    // Empty catch in an auth decision whose tail returns true: ERR-001 only, never also ERR-003.
    public class EmptyCatchAuth : AuthorizeAttribute
    {
        protected override bool AuthorizeCore(HttpContextBase httpContext)
        {
            try
            {
                if (!httpContext.User.IsInRole("admin")) return false;
            }
            catch (Exception)
            {
            }
            return true;
        }
    }

    // Catch that only logs, then falls to the success path of a void filter.
    public class LogOnlyFilter : AuthorizeAttribute
    {
        public override void OnAuthorization(AuthorizationContext filterContext)
        {
            try
            {
                if (!filterContext.HttpContext.User.Identity.IsAuthenticated)
                    filterContext.Result = new HttpUnauthorizedResult();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.WriteLine("auth check failed");
            }
        }
    }

    // Default-deny local: the empty catch leaves ok == false, so it is not fail-open.
    public class DefaultDenyHelper
    {
        public bool CanSee(IPrincipal user)
        {
            bool ok = false;
            try
            {
                ok = user.IsInRole("reader");
            }
            catch (Exception)
            {
            }
            return ok;
        }
    }

    // The auth decision lives in a callee; the catch around the call is fail-open.
    public class CalleeAuth
    {
        private bool Check(IPrincipal user) { return user.IsInRole("ops"); }

        public bool Allowed(IPrincipal user)
        {
            try
            {
                return Check(user);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.TraceError("check failed");
                return true;
            }
        }
    }

    // A catch around unrelated work in an action that merely checks a role is not an auth decision catch.
    public class ActionWithRole : Controller
    {
        public ActionResult Purge()
        {
            if (!User.IsInRole("admin")) return new HttpUnauthorizedResult();
            try
            {
                System.IO.File.Delete("x");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.TraceWarning("purge failed");
            }
            return Content("done");
        }
    }
}
