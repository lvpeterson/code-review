using System;
using System.Security.Principal;
using System.Web;
using System.Web.Mvc;

namespace TaintCs.Errors
{
    // Values assigned inside the try, and everything reachable after a swallowed catch.
    public class TfAuth
    {
        private const bool Ok = true;
        private bool Yes() { return true; }
        private void Work() { }

        public bool TryNot(IPrincipal u)
        {
            bool allowed = false;
            try { allowed = !false; u.IsInRole("a"); }
            catch { return allowed; }
            return false;
        }

        public bool TryConst(IPrincipal u)
        {
            bool allowed = false;
            try { allowed = Ok; u.IsInRole("a"); }
            catch { return allowed; }
            return false;
        }

        public bool TryCall(IPrincipal u)
        {
            bool allowed = false;
            try { allowed = Yes(); u.IsInRole("a"); }
            catch { return allowed; }
            return false;
        }

        public bool TryOrTrue(IPrincipal u)
        {
            bool allowed = false;
            try { allowed = u.IsInRole("a") || true; }
            catch { return allowed; }
            return false;
        }

        // Safe: the try only ever assigns false or the decision itself.
        public bool TryFalse(IPrincipal u)
        {
            bool allowed = false;
            try { allowed = false; u.IsInRole("a"); }
            catch { return allowed; }
            return false;
        }
    }

    public class TfController : Controller
    {
        private void Work() { }
        private void DeleteAll() { }

        public ActionResult RedirectIsSuccess()
        {
            try { if (!User.IsInRole("a")) return new HttpUnauthorizedResult(); }
            catch { }
            DeleteAll();
            return RedirectToAction("Index");
        }

        // Safe: the redirect is the first thing that runs after the catch.
        public ActionResult RedirectFirst()
        {
            try { if (!User.IsInRole("a")) return new HttpUnauthorizedResult(); }
            catch { }
            return RedirectToAction("Login");
        }

        public ActionResult ConditionalSuccessThenThrow()
        {
            try { if (!User.IsInRole("a")) return new HttpUnauthorizedResult(); }
            catch { }
            if (Request.IsAjaxRequest()) return View();
            throw new InvalidOperationException();
        }

        public ActionResult NestedSuccessThenThrow(bool a, bool b)
        {
            try { if (!User.IsInRole("a")) return new HttpUnauthorizedResult(); }
            catch { }
            if (a) { if (b) { return View(); } }
            throw new InvalidOperationException();
        }

        // Safe: nothing reachable returns before the unconditional throw.
        public ActionResult OnlyThrowReachable(bool a)
        {
            try { if (!User.IsInRole("a")) return new HttpUnauthorizedResult(); }
            catch { }
            if (a) { Work(); }
            throw new InvalidOperationException();
        }
    }
}
