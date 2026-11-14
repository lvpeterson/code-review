using System;
using System.Security.Principal;
using System.Web;
using System.Web.Mvc;

namespace TaintCs.Errors
{
    // Locals with several value sources, member targets, and conditional denials in the tail.
    public class R2Auth
    {
        public bool Allowed { get; set; }

        public bool T1NoInit(IPrincipal u)
        {
            bool allowed;
            allowed = true;
            try { allowed = u.IsInRole("a"); }
            catch { return allowed; }
            return allowed;
        }

        public bool T1Reassigned(IPrincipal u, bool flag)
        {
            bool allowed = false;
            if (flag) allowed = true;
            try { allowed = u.IsInRole("a"); }
            catch { return allowed; }
            return allowed;
        }

        public bool T1TryAssignsTrue(IPrincipal u)
        {
            bool allowed = false;
            try { allowed = true; u.IsInRole("a"); }
            catch { return allowed; }
            return false;
        }

        // Safe: the only pre-try value is false and the catch returns it.
        public bool T1Safe(IPrincipal u)
        {
            bool allowed = false;
            try { allowed = u.IsInRole("a"); }
            catch { return allowed; }
            return allowed;
        }

        public bool T2This(IPrincipal u)
        {
            try { this.Allowed = u.IsInRole("a"); }
            catch { this.Allowed = true; }
            return this.Allowed;
        }

        public bool T2Bare(IPrincipal u)
        {
            try { Allowed = u.IsInRole("a"); }
            catch { Allowed = true; }
            return Allowed;
        }

        public bool T2Safe(IPrincipal u)
        {
            try { this.Allowed = u.IsInRole("a"); }
            catch { this.Allowed = false; }
            return this.Allowed;
        }
    }

    public class R2Controller : Controller
    {
        public ActionResult T3Throw()
        {
            try { if (!User.IsInRole("a")) return new HttpUnauthorizedResult(); }
            catch { }
            if (Request == null) throw new InvalidOperationException();
            return View();
        }

        public ActionResult T3Redirect()
        {
            try { if (!User.IsInRole("a")) return new HttpUnauthorizedResult(); }
            catch { }
            if (Request.Url == null) { return Redirect("/x"); }
            return View();
        }

        // Safe: the tail denies unconditionally (empty catch still reports ERR-003).
        public ActionResult T3SafeReturn()
        {
            try { if (!User.IsInRole("a")) return new HttpUnauthorizedResult(); }
            catch { }
            return new HttpUnauthorizedResult();
        }

        public ActionResult T3SafeThrow()
        {
            try { if (!User.IsInRole("a")) return new HttpUnauthorizedResult(); }
            catch { }
            throw new InvalidOperationException();
        }

        public ActionResult HeaderAdd()
        {
            try { View(); }
            catch (Exception ex) { Response.AddHeader("X-E", ex.Message); }
            return View();
        }

        public ActionResult HeadersAdd()
        {
            try { View(); }
            catch (Exception ex) { Response.Headers.Add("X-E", ex.Message); }
            return View();
        }
    }
}
